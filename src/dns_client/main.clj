(ns dns-client.main
  (:gen-class)
  (:require
   [clojure.edn :as edn]
   [clojure.pprint :as pprint]
   [clojure.string :as str]
   [jdk.net.DatagramPacket :as packet]
   [jdk.net.DatagramSocket :as sock]
   [jdk.net.InetAddress :as addr]))

(def max-value (Short/toUnsignedInt (short -1)))

(defn num->byte-pair [num]
  (reverse
   (sequence (comp (map (memfn ^Long byteValue))
                   (take 2))
             (iterate #(bit-shift-right % 8) (long num)))))

(defn byte-pair->num [[b1 b2]]
  (bit-or (bit-shift-left (Byte/toUnsignedLong b1) 8) (Byte/toUnsignedLong b2)))

(def default-server
  "8.8.8.8")

(def root-server
  "192.203.230.10")

(def ^:private qr 2r0) ;; 0 for query, 1 for response
(def ^:private opcode 2r0000) ;;  0 for standard query
(def ^:private aa 2r0) ;; 0 for non-authoritative answer, only valid for responses
(def ^:private tc 2r0) ;; 0 for not truncated due to length greater than the packet size
(def ^:private rd 2r1) ;; 1 for recursion desired, support is optional
(def ^:private ra 2r0) ;; For recursion availability, set or cleared in a response
(def ^:private z 2r000) ;; Reserved for future use, must be zero in all queries and responses
(def ^:private rcode 2r0000) ;; Response code, 0 for no error, 1 for format error, 2 for server failure, etc.
(def ^:private flags (num->byte-pair (bit-or (bit-shift-left qr 15)
                                             (bit-shift-left opcode 11)
                                             (bit-shift-left aa 10)
                                             (bit-shift-left tc 9)
                                             (bit-shift-left rd 8)
                                             (bit-shift-left ra 7)
                                             (bit-shift-left z 4)
                                             rcode)))
(def ^:private qdcount (num->byte-pair 1)) ;; 1 question
(def ^:private ancount (num->byte-pair 0)) ;; 0 answers
(def ^:private nscount (num->byte-pair 0)) ;; 0 authority records
(def ^:private arcount (num->byte-pair 1)) ;; 0 additional records
(def host-address-qtype (num->byte-pair 1)) ;; A record type (host address)
(def ns-qtype (num->byte-pair 2));; NS record type (name server)
(def cname-qtype (num->byte-pair 5)) ;; CNAME record type (canonical name)
(def soa-qtype (num->byte-pair 6)) ;; SOA record type (start of authority)
(def ptr-qtype (num->byte-pair 12)) ;; PTR record type (pointer to another domain name)
(def mx-qtype (num->byte-pair 15)) ;; MX record type (mail exchange)
(def aaaa-qtype (num->byte-pair 28)) ;; AAAA record type (IPv6 address)
(def opt-qtype (num->byte-pair 41)) ;; OPT record type (EDNS0 option)
(def any-qtype (num->byte-pair 255)) ;; ANY record type (any type of record)
(def ^:private qclass (num->byte-pair 1)) ;; IN class (Internet)
(def ^:private root-label [0x00]) ;; Root label (0x00)
(def ^:private udp-payload-size (num->byte-pair 4096)) ;; EDNS0 (fits in class standard rr section)
(def ^:private ttl-pseudo [0x00 0x00 0x00 0x00]) ;; Pseudo-ttl for EDNS0
(def ^:private rdlen-pseudo (num->byte-pair 0)) ;; Pseudo-rdlen for EDNS0
(def ^:private max-label-references 16)

(defn random-id []
  (num->byte-pair (rand-int max-value)))

(defn- qname [dname]
  (conj
   (->> (str/split dname #"\.")
        (filter not-empty)
        (reduce (fn [acc label] (apply conj acc (count label) (.getBytes label))) []))
   0x00))

(defn- parse-header [response]
  (let [[raw-header remaining] (split-at 12 response)
        [id flags qdcount ancount nscount arcount] (partition 2 raw-header)
        flags-num (byte-pair->num flags)]
    [{:id (byte-pair->num id)
      :flags {:qr (bit-shift-right flags-num 15)
              :opcode (bit-and (bit-shift-right flags-num 11) 0x0F)
              :aa (bit-and (bit-shift-right flags-num 10) 0x01)
              :tc (bit-and (bit-shift-right flags-num 9) 0x01)
              :rd (bit-and (bit-shift-right flags-num 8) 0x01)
              :ra (bit-and (bit-shift-right flags-num 7) 0x01)
              :z (bit-and (bit-shift-right flags-num 4) 0x07)
              :rcode (bit-and flags-num 0x0F)}
      :qdcount (byte-pair->num qdcount)
      :ancount (byte-pair->num ancount)
      :nscount (byte-pair->num nscount)
      :arcount (byte-pair->num arcount)}
     remaining]))

(defn stringify-labels [separator labels]
  (str/join separator (map (comp #(String. %) byte-array) labels)))

(defn expand-labels*
  [remaining search-area & {:keys [depth] :or {depth 0}}]
  (loop [acc [] len 0 [oc1 oc2 :as remaining] remaining]
    (cond (= 0x00 oc1) [acc (rest remaining)]
          (> depth max-label-references) (throw (ex-info "Too many labels" {:data remaining}))
          (= 0xC0 (bit-and oc1 0xC0))
          (let [offset (byte-pair->num [(bit-and oc1 0x3F) oc2])]
            [(into acc (first (expand-labels* (drop offset search-area) search-area :depth (inc depth))))
             (drop 2 remaining)])
          :else
          (let [label-len oc1
                label (take label-len (rest remaining))]
            (recur (conj acc label) (+ len 1 label-len) (drop (inc label-len) remaining))))))

(defn expand-labels
  [remaining search-area & opts]
  (let [[labels remaining] (expand-labels* remaining search-area opts)]
    [(stringify-labels "." labels) remaining]))

(defn- parse-question [remaining response]
  (let [[qname-labels remaining] (expand-labels remaining response)
        [qtype remaining] (split-at 2 remaining)
        [qclass remaining] (split-at 2 remaining)]
    [{:qname qname-labels
      :qtype (byte-pair->num qtype)
      :qclass (byte-pair->num qclass)}
     remaining]))

(defn- ipv4-labels [remaining]
  (let [ip-ints (take 4 remaining)]
    [(stringify-labels "." (map (comp seq (memfn ^String getBytes) str #(Byte/toUnsignedLong %))
                                ip-ints))
     (drop 4 remaining)]))

(defn- ipv6-labels [remaining]
  (let [ip-int-pairs (partition 2 (take 16 remaining))]
    [(stringify-labels ":" (map (comp seq (memfn ^String getBytes) #(Long/toHexString %) byte-pair->num)
                                ip-int-pairs))
     (drop 16 remaining)]))

(defn- text-rdata [rdlen remaining]
  (let [[text-data remaining] (split-at rdlen remaining)]
    [(stringify-labels "." [text-data]) remaining]))

(defn- mx-rdata [remaining response]
  (let [[preference remaining] (split-at 2 remaining)
        [exchange-labels remaining] (expand-labels remaining response)]
    [{:preference (byte-pair->num preference)
      :exchange exchange-labels}
     remaining]))

(defn- soa-rdata [remaining response]
  (let [[mname-labels remaining] (expand-labels remaining response)
        [rname-labels remaining] (expand-labels remaining response)
        [serial remaining] (split-at 4 remaining)
        [refresh remaining] (split-at 4 remaining)
        [retry remaining] (split-at 4 remaining)
        [expire remaining] (split-at 4 remaining)
        [minimum remaining] (split-at 4 remaining)]
    [{:mname mname-labels
      :rname rname-labels
      :serial serial
      :refresh refresh
      :retry retry
      :expire expire
      :minimum minimum}
     remaining]))

(defn- parse-rrs [remaining response rr-num]
  (loop [acc [] remaining remaining rr-num rr-num]
    (if (zero? rr-num)
      [acc remaining]
      (let [[name-labels remaining] (expand-labels remaining response)
            [type remaining] (split-at 2 remaining)
            [class remaining] (split-at 2 remaining)
            [ttl remaining] (split-at 4 remaining)
            [rdlen remaining] (split-at 2 remaining)
            [rdata-labels remaining] (condp = type
                                       host-address-qtype (ipv4-labels remaining)
                                       ns-qtype (expand-labels remaining response)
                                       cname-qtype (expand-labels remaining response)
                                       soa-qtype (soa-rdata remaining response)
                                       ptr-qtype (expand-labels remaining response)
                                       mx-qtype (mx-rdata remaining response)
                                       aaaa-qtype (ipv6-labels remaining)
                                       (text-rdata (byte-pair->num rdlen) remaining))]
        (recur (conj acc {:name name-labels
                          :type (byte-pair->num type)
                          :class (byte-pair->num class)
                          :ttl ttl
                          :rdlen (byte-pair->num rdlen)
                          :rdata rdata-labels})
               remaining
               (dec rr-num))))))

(defn- parse-response [response]
  (let [[header remaining] (parse-header response)
        [question remaining] (parse-question remaining response)
        [answer remaining] (parse-rrs remaining response (:ancount header))
        [authority remaining] (parse-rrs remaining response (:nscount header))
        [additional] (parse-rrs remaining response (:arcount header))]
    {:header header
     :question question
     :answer answer
     :authority authority
     :additional additional}))

(defn dns-request [server request]
  (with-open [socket (sock/->datagram-socket)]
    (let [name-server-address (addr/*get-by-name server)
          send-packet (packet/->datagram-packet (byte-array request) (count request) name-server-address 53)
          arr-ret (byte-array 4096)
          recv-packet (packet/->datagram-packet arr-ret (alength arr-ret))
          _ (sock/set-so-timeout socket 1000)
          _ (sock/send socket send-packet)
          _ (sock/receive socket recv-packet)]
      (packet/get-data recv-packet))))

(defn query-dns-server [{:keys [dname qtype server] :as opts
                         :or {dname "slack.com" qtype host-address-qtype server default-server}}]
  (let [id (random-id)
        header (concat id flags qdcount ancount nscount arcount)
        question (concat (qname dname) qtype qclass)
        edns0 (concat root-label opt-qtype udp-payload-size ttl-pseudo rdlen-pseudo)
        response (dns-request server (concat header question edns0))
        parsed-response (delay (parse-response response))]
    (when (not= id (take 2 response))
      (throw (ex-info "ID does not match response's ID" {:data response})))
    (pprint/pprint @parsed-response)
    (if-let [[{server-dname :rdata}] (and (:trace? opts)
                                          (empty? (:answer @parsed-response))
                                          (->> @parsed-response
                                               :authority
                                               (filter (comp (partial = 2) :type))
                                               not-empty))]
      (let [server-address (or (some #(when (and (= (:name %) server-dname)
                                                 (= (:type %) 1)) (:rdata %))
                                     (:additional @parsed-response))
                               (->> {:trace? true
                                     :dname server-dname
                                     :qtype host-address-qtype
                                     :server root-server}
                                    query-dns-server :answer first :rdata))]
        (some->> server-address
                 (assoc opts :server)
                 query-dns-server))
      @parsed-response)))

(defn handle-dns-query [{:keys [trace?] :as opts :or {trace? false}}]
  (query-dns-server (cond-> opts trace? (assoc :server root-server))))

(defn -main [opts]
  (handle-dns-query (cond-> opts (string? opts) edn/read-string)))

(comment
  (-main {:dname "google.com" :server "192.5.5.241"})
  (-main {:dname "wikipedia.org" :server "192.203.230.10"})
  (-main {:dname "twitter.com" :trace? true})
  (-main {:qtype ns-qtype :dname "google.com" :server "216.239.34.10"})
  (-main {:qtype host-address-qtype :dname "google.com" :server "216.239.34.10"})
  (-main {:qtype mx-qtype :dname "google.com"})
  (-main {:qtype aaaa-qtype :dname "ipv6.google.com"})
  (-main {:qtype ptr-qtype :dname "8.8.8.8.in-addr.arpa"})
  (-main {:qtype any-qtype :dname "google.com"}))

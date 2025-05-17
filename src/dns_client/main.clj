(ns dns-client.main
  (:gen-class)
  (:require [clojure.string :as str]
            [jdk.net.DatagramSocket :as sock]
            [jdk.net.InetAddress :as addr]
            [jdk.net.DatagramPacket :as packet]))

(def max-value (Short/toUnsignedInt (short -1)))

(defn num->byte-pair [num]
  (reverse
   (sequence (comp (map (memfn ^Long byteValue))
                   (take 2))
             (iterate #(bit-shift-right % 8) (long num)))))

(defn byte-pair->num [[b1 b2]]
  (bit-or (bit-shift-left (Byte/toUnsignedLong b1) 8) (Byte/toUnsignedLong b2)))

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
(def ^:private arcount (num->byte-pair 0)) ;; 0 additional records
(def ^:private host-address-qtype (num->byte-pair 1)) ;; A record type (host address)
(def ^:private ns-qtype (num->byte-pair 2)) ;; NS record type (name server)
(def ^:private qclass (num->byte-pair 1)) ;; IN class (Internet)
(def ^:private max-label-references 16)

(defn- random-id []
  (num->byte-pair (rand-int max-value)))

(defn- qname [dname]
  (conj
   (->> (str/split dname #"\.")
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

(defn stringify-labels [labels]
  (str/join "." (map (comp #(String. %) byte-array) labels)))

(defn expand-labels [remaining search-area & {:keys [depth] :or {depth 0}}]
  (loop [acc [] len 0 [oc1 oc2 :as remaining] remaining]
    (cond (= 0x00 oc1) [acc (rest remaining)]
          (> depth max-label-references) (throw (ex-info "Too many labels" {:data remaining}))
          (= 0xC0 (bit-and oc1 0xC0))
          (let [offset (byte-pair->num [(bit-and oc1 0x3F) oc2])]
            [(into acc (first (expand-labels (drop offset search-area) search-area :depth (inc depth))))
             (drop 2 remaining)])
          :else
          (let [label-len oc1
                label (take label-len (rest remaining))]
            (recur (conj acc label) (+ len 1 label-len) (drop (inc label-len) remaining))))))

(defn- parse-question [remaining response]
  (let [[qname-labels remaining] (expand-labels remaining response)
        [qtype remaining] (split-at 2 remaining)
        [qclass remaining] (split-at 2 remaining)]
    [{:qname (stringify-labels qname-labels)
      :qtype (byte-pair->num qtype)
      :qclass (byte-pair->num qclass)}
     remaining]))

(defn- ip-labels [remaining]
  (let [ip-ints (take 4 remaining)]
    [(map (comp seq (memfn ^String getBytes) str #(Byte/toUnsignedLong %)) ip-ints)
     (drop 4 remaining)]))

(defn- parse-rrs [remaining response rr-num]
  (loop [acc [] remaining remaining rr-num rr-num]
    (if (zero? rr-num)
      [acc remaining]
      (let [[name-labels remaining] (expand-labels remaining response)
            [type remaining] (split-at 2 remaining)
            [class remaining] (split-at 2 remaining)
            [ttl remaining] (split-at 4 remaining)
            [rdlen remaining] (split-at 2 remaining)
            [rdata-labels remaining] (case (byte-pair->num type)
                                       1 (ip-labels remaining)
                                       2 (expand-labels remaining response))]
        (recur (conj acc {:name (stringify-labels name-labels)
                          :type (byte-pair->num type)
                          :class (byte-pair->num class)
                          :ttl ttl
                          :rdlen (byte-pair->num rdlen)
                          :rdata (stringify-labels rdata-labels)})
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

(defn query-server [{:keys [dname qtype] :or {dname "slack.com" qtype host-address-qtype}}]
  (with-open [socket (sock/->datagram-socket)]
    (let [id (random-id)
          header (concat id flags qdcount ancount nscount arcount)
          question (concat (qname dname) qtype qclass)
          name-server-address (addr/*get-by-name "1.1.1.1")
          arr-req (byte-array (concat header question))
          send-packet (packet/->datagram-packet arr-req (alength arr-req) name-server-address 53)
          arr-ret (byte-array 4096)
          recv-packet (packet/->datagram-packet arr-ret (alength arr-ret))
          _ (sock/send socket send-packet)
          _ (sock/receive socket recv-packet)
          response (packet/get-data recv-packet)]
      (if (= id (take 2 response))
        (parse-response response)
        (throw (ex-info "ID does not match response's ID" {:data response}))))))

(defn -main [& opts]
  (query-server opts))

(comment
  (-main :dname "example.com")
  (-main :qtype ns-qtype))

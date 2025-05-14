(ns main
  (:gen-class)
  (:require
   [clojure.string :as str]
   [jdk.net.DatagramSocket :as sock]
   [jdk.net.InetAddress :as addr]
   [jdk.net.DatagramPacket :as packet]))

(defn to-byte-pair [num]
  (reverse
   (sequence (comp (map (memfn ^Long byteValue))
                   (take 2))
             (iterate #(bit-shift-right % 8) (long num)))))

(def qr 2r0)
(def opcode 2r0000)
(def aa 2r0)
(def tc 2r0)
(def rd 2r1)
(def ra 2r0)
(def z 2r000)
(def rcode 2r0000)
(def flags (to-byte-pair
            (bit-or (bit-shift-left qr 15)
                    (bit-shift-left opcode 11)
                    (bit-shift-left aa 10)
                    (bit-shift-left tc 9)
                    (bit-shift-left rd 8)
                    (bit-shift-left ra 7)
                    (bit-shift-left z 4)
                    rcode)))
(def qdcount (to-byte-pair 0x01))
(def ancount (to-byte-pair 0x00))
(def nscount (to-byte-pair 0x00))
(def arcount (to-byte-pair 0x00))

(defn- random-id []
  (to-byte-pair (rand-int Short/MAX_VALUE)))

(defn- qname [dname]
  (conj
   (->> (str/split dname #"\.")
        (reduce (fn [acc label] (apply conj acc (count label) (.getBytes label))) []))
   0x00))

(defn query-server [dname]
  (with-open [socket (sock/->datagram-socket)]
    (let [id (random-id)
          header (concat id flags qdcount ancount nscount arcount)
          internet-address-meta [0x00 0x01 0x00 0x01]
          qname (qname dname)
          address (addr/*get-by-name "1.1.1.1")
          arr (byte-array (concat header qname internet-address-meta))
          send-packet (packet/->datagram-packet arr (alength arr) address 53)
          arr-ret (byte-array 4096)
          recv-packet (packet/->datagram-packet arr-ret (alength arr-ret))
          _ (sock/send socket send-packet)
          _ (sock/receive socket recv-packet)
          data (packet/get-data recv-packet)]
      (if (= id (take 2 data))
        data
        (throw (ex-info "ID does not match response's ID" {:data data}))))))

(defn -main [& [dname]]
  (query-server (or dname "slack.com")))

(comment
  (mapv (partial format "%x") (-main "example.com"))
  (mapv (partial format "%x") (-main)))

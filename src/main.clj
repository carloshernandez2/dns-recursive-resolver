(ns main
  (:gen-class)
  (:require
   [clojure.string :as str]
   [jdk.net.DatagramSocket :as sock]
   [jdk.net.InetAddress :as addr]
   [jdk.net.DatagramPacket :as packet]))

(defn qname [dname]
  (conj
   (->> (str/split dname #"\.")
        (reduce (fn [acc label] (apply conj acc (count label) (.getBytes label))) []))
   0x00))

(defn -main [& [address]]
  (with-open [socket (sock/->datagram-socket)]
    (let [header [0xd8 0xbf 0x01 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00]
          internet-address-meta [0x00 0x01 0x00 0x01]
          qname (qname (or address "slack.com"))
          address (addr/*get-by-name "1.1.1.1")
          arr (byte-array (concat header qname internet-address-meta))
          send-packet (packet/->datagram-packet arr (alength arr) address 53)
          arr-ret (byte-array 4096)
          recv-packet (packet/->datagram-packet arr-ret (alength arr-ret))]
      (sock/send socket send-packet)
      (sock/receive socket recv-packet)
      (packet/get-data recv-packet))))

(comment
  (mapv (partial format "%x") (-main "example.com"))
  (mapv (partial format "%x") (-main)))

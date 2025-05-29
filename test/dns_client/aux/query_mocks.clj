(ns dns-client.aux.query-mocks)

(def random-id [-66 -96])

(def ns-request
  [-66 -96 1 0 0 1 0 0 0 0 0 1 5 115 108 97 99 107 3 99 111 109 0 0 2 0 1 0 0 41 16 0 0 0 0 0 0 0])

(def a-request
  [-66 -96 1 0 0 1 0 0 0 0 0 1 5 115 108 97 99 107 3 99 111 109 0 0 1 0 1 0 0 41 16 0 0 0 0 0 0 0])

(def ptr-request
  [-66 -96 1 0 0 1 0 0 0 0 0 1 1 56 1 56 1 56 1 56 7 105 110 45 97 100 100 114 4 97 114 112 97 0 0 12 0 1 0 0 41 16 0 0 0 0 0 0 0])

(def ns-response
  (byte-array [-66 -96 -127 -128 0 1 0 4 0 0 0 0 5 115 108 97 99 107 3 99 111 109 0 0 2 0 1 -64 12 0 2 0 1 0 0 10 -85 0 19 6 110 115 45 49 54 54 9 97 119 115 100 110 115 45 50 48 -64 18 -64 12 0 2 0 1 0 0 10 -85 0 22 6 110 115 45 54 48 54 9 97 119 115 100 110 115 45 49 49 3 110 101 116 0 -64 12 0 2 0 1 0 0 10 -85 0 23 7 110 115 45 49 52 57 51 9 97 119 115 100 110 115 45 53 56 3 111 114 103 0 -64 12 0 2 0 1 0 0 10 -85 0 25 7 110 115 45 49 57 48 49 9 97 119 115 100 110 115 45 52 53 2 99 111 2 117 107 0]))

(def a-response
  (byte-array [-66 -96 -127 -128 0 1 0 15 0 0 0 0 5 115 108 97 99 107 3 99 111 109 0 0 1 0 1 -64 12 0 1 0 1 0 0 0 31 0 4 34 -53 97 10 -64 12 0 1 0 1 0 0 0 31 0 4 3 -46 88 6 -64 12 0 1 0 1 0 0 0 31 0 4 34 -63 -1 5 -64 12 0 1 0 1 0 0 0 31 0 4 34 -60 46 -54 -64 12 0 1 0 1 0 0 0 31 0 4 54 -109 59 -87 -64 12 0 1 0 1 0 0 0 31 0 4 34 -54 -3 6 -64 12 0 1 0 1 0 0 0 31 0 4 34 -52 109 -30 -64 12 0 1 0 1 0 0 0 31 0 4 54 -93 -21 119 -64 12 0 1 0 1 0 0 0 31 0 4 34 -31 62 -71 -64 12 0 1 0 1 0 0 0 31 0 4 34 -25 24 -32 -64 12 0 1 0 1 0 0 0 31 0 4 54 -31 -103 -51 -64 12 0 1 0 1 0 0 0 31 0 4 54 92 -57 -70 -64 12 0 1 0 1 0 0 0 31 0 4 34 -51 -61 66 -64 12 0 1 0 1 0 0 0 31 0 4 3 95 117 96 -64 12 0 1 0 1 0 0 0 31 0 4 52 73 -116 59 0]))

(def ptr-response
  (byte-array [-66 -96 -127 -128 0 1 0 1 0 0 0 0 1 56 1 56 1 56 1 56 7 105 110 45 97 100 100 114 4 97 114 112 97 0 0 12 0 1 -64 12 0 12 0 1 0 1 26 -114 0 12 3 100 110 115 6 103 111 111 103 108 101 0]))

(def ns-parsed-response
  {:header {:id 48800
            :flags {:qr 1
                    :opcode 0
                    :aa 0
                    :tc 0
                    :rd 1
                    :ra 1
                    :z 0
                    :rcode 0}
            :qdcount 1
            :ancount 4
            :nscount 0
            :arcount 0}
   :question {:qname "slack.com"
              :qtype 2
              :qclass 1}
   :answer [{:name "slack.com"
             :type 2
             :class 1
             :ttl [0 0 10 -85]
             :rdlen 19
             :rdata "ns-166.awsdns-20.com"}
            {:name "slack.com"
             :type 2
             :class 1
             :ttl [0 0 10 -85]
             :rdlen 22
             :rdata "ns-606.awsdns-11.net"}
            {:name "slack.com"
             :type 2
             :class 1
             :ttl [0 0 10 -85]
             :rdlen 23
             :rdata "ns-1493.awsdns-58.org"}
            {:name "slack.com"
             :type 2
             :class 1
             :ttl [0 0 10 -85]
             :rdlen 25
             :rdata "ns-1901.awsdns-45.co.uk"}]
   :authority []
   :additional []})

(def a-parsed-response
  {:header {:id 48800
            :flags {:qr 1
                    :opcode 0
                    :aa 0
                    :tc 0
                    :rd 1
                    :ra 1
                    :z 0
                    :rcode 0}
            :qdcount 1
            :ancount 15
            :nscount 0
            :arcount 0}
   :question {:qname "slack.com"
              :qtype 1
              :qclass 1}
   :answer [{:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.203.97.10"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "3.210.88.6"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.193.255.5"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.196.46.202"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "54.147.59.169"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.202.253.6"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.204.109.226"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "54.163.235.119"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.225.62.185"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.231.24.224"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "54.225.153.205"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "54.92.199.186"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "34.205.195.66"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "3.95.117.96"}
            {:name "slack.com"
             :type 1
             :class 1
             :ttl [0 0 0 31]
             :rdlen 4
             :rdata "52.73.140.59"}]
   :authority []
   :additional []})

(def ptr-parsed-response
  {:header {:id 48800
            :flags {:qr 1
                    :opcode 0
                    :aa 0
                    :tc 0
                    :rd 1
                    :ra 1
                    :z 0
                    :rcode 0}
            :qdcount 1
            :ancount 1
            :nscount 0
            :arcount 0}
   :question {:qname "8.8.8.8.in-addr.arpa"
              :qtype 12
              :qclass 1}
   :answer [{:name "8.8.8.8.in-addr.arpa"
             :type 12
             :class 1
             :ttl [0 1 26 -114]
             :rdlen 12
             :rdata "dns.google"}]
   :authority []
   :additional []})

(ns dns-client.main-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [mockfn.macros :as mfn]
   [dns-client.main :as main]
   [dns-client.aux.query-mocks :as query-mocks]))

(defspec byte-pair-long 100
  (prop/for-all [num (gen/choose 0 main/max-value)]
                (let [byte-pair (main/num->byte-pair num)
                      long-num (main/byte-pair->num byte-pair)]
                  (= num long-num))))

(deftest expand-labels-test
  (testing "Gets single label from a domain name and returns a list of remaining bytes"
    (is (= ["www" [0x02 0x77 0x77 0x00]]
           (main/expand-labels [0x03 0x77 0x77 0x77 0x00 0x02 0x77 0x77 0x00] []))))
  (testing "Splits a domain name into many labels"
    (is (= ["www.ww" []]
           (main/expand-labels [3 119 119 119 2 119 119 0] []))))
  (testing "Correctly creates labels recursively via pointers"
    (is (= ["www.ww" [0x01 0x01 0x01]]
           (main/expand-labels [0xC0 0x02 0x01 0x01 0x01]
                               [0x01 0x01 0x03 0x77 0x77 0x77 0xC0 0x0F
                                0x01 0x01 0x01 0x03 0x77 0x77 0x77 0x02
                                0x77 0x77 0x00 0xC0 0x02 0x01 0x01 0x01]))))
  (testing "Throws after a bound number of label references to avoid infinite loops"
    (is (thrown-with-msg? Exception
                          #"Too many labels"
                          (main/expand-labels [0xC0 0x00] [0xC0 0x00])))))

(deftest ip-labels-test
  (is (= ["255.2.3.4" [0xC0 0x02 0x01 0x01 0x01]]
         (#'main/ipv4-labels [-0x01 0x02 0x03 0x04 0xC0 0x02 0x01 0x01 0x01]))))

(deftest query-dns-server-test
  (testing "Supports processing NS queries"
    (mfn/providing [(main/dns-request main/default-server query-mocks/ns-request) query-mocks/ns-response
                    (main/random-id) query-mocks/random-id]
                   (is (= query-mocks/ns-parsed-response (main/query-dns-server {:qtype main/ns-qtype})))))
  (testing "Supports processing A queries"
    (mfn/providing [(main/dns-request main/default-server query-mocks/a-request) query-mocks/a-response
                    (main/random-id) query-mocks/random-id]
                   (is (= query-mocks/a-parsed-response (main/query-dns-server {:qtype main/host-address-qtype})))))
  (testing "Supports processing PTR queries"
    (mfn/providing [(main/dns-request main/default-server query-mocks/ptr-request) query-mocks/ptr-response
                    (main/random-id) query-mocks/random-id]
                   (is (= query-mocks/ptr-parsed-response (main/query-dns-server {:qtype main/ptr-qtype
                                                                                  :dname "8.8.8.8.in-addr.arpa"}))))))

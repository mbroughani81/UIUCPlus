#!/usr/bin/env bb

(require '[clojure.java.shell :refer [sh]]
         '[cheshire.core :as json])

(defn execute-commands [work-dir commands]
  ;; Iterate over each command and execute it within the working directory
  (doseq [cmd commands]
    (println "Executing command in directory:" work-dir "Command:" cmd)
    (let [result (sh "bash" "-c" (str "source scripts/env" " && " "cd " work-dir " && " cmd))]
      (println "stdout:" (:out result))
      (println "stderr:" (:err result))
      (when (not= 0 (:exit result))
        (println "Error:" (:exit result) "while executing command:" cmd)
        (throw (ex-info "Command execution failed" {:exit-code (:exit result)}))))
    (println "===============================")))

;; Assuming the JSON file is named config.json and located in the scripts directory
(let [json-content (slurp "scripts/config.json")
      config       (json/parse-string json-content true)
      mutations    (:mutations config)]

  ;; Iterate over each mutation
  (doseq [mutation mutations]
    (execute-commands (:directory mutation) (:commands mutation))))
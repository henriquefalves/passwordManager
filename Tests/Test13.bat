cd ../PasswordManager
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=8006 0"
start cmd /k mvn exec:java "-Dexec.args=8007 0"
start cmd /k mvn exec:java "-Dexec.args=8008 0"
start cmd /k mvn exec:java "-Dexec.args=8009 0"
start cmd /k mvn exec:java "-Dexec.args=8010 0"
start cmd /k mvn exec:java "-Dexec.args=8011 0"
start cmd /k mvn exec:java "-Dexec.args=8012 3"
start cmd /k mvn exec:java "-Dexec.args=8013 3"
cd ../Client
call mvn clean compile
start cmd /k mvn exec:java "-Dexec.args=1 localhost password-manager 8006 8007 8008 8009 8010 8011 8012 8013 "
start cmd /k mvn exec:java "-Dexec.args=2 localhost password-manager 8006 8007 8008 8009 8010 8011 8012 8013 "
start cmd /k mvn exec:java "-Dexec.args=3 localhost password-manager 8006 8007 8008 8009 8010 8011 8012 8013 "

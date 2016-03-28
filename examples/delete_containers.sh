# !/bin/bash

for ((i=0; i<20; i++)); do
  curl -i -X DELETE -H 'X-Storage-Token: AUTH_tk9b8e15036d884761b4b144697d9ffe72' http://127.0.0.1:8080/v1/AUTH_test/90ef17063d3e406ba20a179134de22f0_$i
  curl -i -X DELETE -H 'X-Storage-Token: AUTH_tk9b8e15036d884761b4b144697d9ffe72' http://127.0.0.1:8080/v1/AUTH_test/4b6e635a35644494a29cf98e2b2ca181_$i
  curl -i -X DELETE -H 'X-Storage-Token: AUTH_tk9b8e15036d884761b4b144697d9ffe72' http://127.0.0.1:8080/v1/AUTH_test/65290da27c814b3e81a6343b4c39bd2b_$i
  curl -i -X DELETE -H 'X-Storage-Token: AUTH_tk9b8e15036d884761b4b144697d9ffe72' http://127.0.0.1:8080/v1/AUTH_test/8036db6b313c4d80a308691899ec20aa_$i
done



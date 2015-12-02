#!/bin/bash 

#user_name='test:tester'
#passwd='testing'
#auth_url='http://127.0.0.1:8080/auth/v1.0'

#auth_request=$(curl -i -H 'X-Storage-User: '$user_name -H 'X-Storage-Pass: '$passwd  $auth_url)
#con_name='5ae98846cc9d48b2ba0d72c58c30369b_0'
Token='AUTH_tk4c7d7ee97eb841e4bc79611e5a9bb42a'
curl -i -X GET -H 'X-Auth-Token: '${Token} http://127.0.0.1:8080/v1/AUTH_test >> tmp_container.txt
sed -n '18,$p' tmp_container.txt >> tmp_con.txt

for con_name in `cat tmp_con.txt`; do
  curl -i -X GET -H 'X-Auth-Token: '${Token} http://127.0.0.1:8080/v1/AUTH_test/$con_name >> tmp_object.txt
  sed -n '12,$p' tmp_object.txt >> tmp_obj.txt
  for line in `cat tmp_obj.txt`; do
    curl -X DELETE  -H 'X-Auth-Token: '${Token}  http://127.0.0.1:8080/v1/AUTH_test/$con_name/$line
  done
  rm tmp_obj*
  curl -i -X DELETE -H 'X-Auth-Token: '${Token} http://127.0.0.1:8080/v1/AUTH_test/$con_name  
done

rm tmp*

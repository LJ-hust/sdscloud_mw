# !/bin/bash 

con_name='lijing'
Token='X-Auth-Token: AUTH_tk4baac626106e4c5f983eddb6720b6b0e'

rm var*
curl -i -X GET -H 'X-Auth-Token: AUTH_tk4baac626106e4c5f983eddb6720b6b0e' http://127.0.0.1:8080/v1/AUTH_test/lijing >> var.txt
sed -n '12,$p' var.txt >> var1.txt
chmod 777 var1.txt

for line in `cat ./var1.txt`
do
  curl -X DELETE  -H 'X-Auth-Token: AUTH_tk4baac626106e4c5f983eddb6720b6b0e'  http://127.0.0.1:8080/v1/AUTH_test/$con_name/$line
done

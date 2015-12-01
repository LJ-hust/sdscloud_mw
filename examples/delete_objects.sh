# !/bin/bash 

con_name='5ae98846cc9d48b2ba0d72c58c30369b_0'
Token='AUTH_tk1174caebfc574073914c780a663ab0ee'

curl -i -X GET -H 'X-Auth-Token: '${Token} http://127.0.0.1:8080/v1/AUTH_test/$con_name >> var.txt
sed -n '12,$p' var.txt >> var1.txt
chmod 777 var1.txt

for line in `cat ./var1.txt`
do
  curl -X DELETE  -H 'X-Auth-Token: '${Token}  http://127.0.0.1:8080/v1/AUTH_test/$con_name/$line
done

rm var*

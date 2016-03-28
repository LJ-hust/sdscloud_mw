import re
import uuid

from libcloud.utils.py3 import urlquote
<<<<<<< HEAD

=======
>>>>>>> b280588561ef202377b8aff557fa408a0ab498e4
#edit by liuyun
def sdscloud_container_name_check(container_name):
    #consist of small letter,digit and '-'
    #end or start with small letter or digit
    #length must between 3 an 63
    if not container_name[0].isdigit() and not container_name[0].isalpha():
        return False
    if not container_name[-1].isdigit() and not container_name[-1].isalpha():
        return False
    if len(container_name) < 3 or len(container_name) > 63:
        return False
    pattern = re.compile('[a-z0-9-]+')
    m = pattern.match(container_name)
    if not m or m.group() != container_name:
        return False
    return True

#edit by lijing
def sdscloud_object_name_check(object_name):
    #the first_name can not be '/' or '\'
    #'\n' and '\r' can not be in the name
    #length can not more than 128 byte

    if object_name[0] in ("/","\\"):
        return False

    if "\r" in object_name or "\n" in object_name:
        return False

    object_name = urlquote(object_name)
    if len(object_name) > 128:
        return False

    return True

def swift_bench_name_test():
    container_name = uuid.uuid4().hex + '-20'
    object_name = uuid.uuid4().hex
    print 'container_name:', container_name, sdscloud_container_name_check(container_name)
    print 'object_name:', object_name, sdscloud_object_name_check(object_name)

if __name__ == "__main__":
    swift_bench_name_test()


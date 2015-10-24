import re

from libcloud.utils.py3 import urlquote
from libcloud.storage.types import InvalidObjectNameError

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
        raise InvalidObjectNameError("the first character can not be '/' and '\'")

    if "\r" in object_name or "\n" in object_name:
        raise InvalidObjectNameError("the name can not have '\r' and '\n'")

    object_name = urlquote(object_name)
    if len(object_name) > 128:
        raise InvalidObjectNameError(value='Object name length must less than 128',object_name=object_name)

    return True
    pass

if __name__ == "__main__":
    main()


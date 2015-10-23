import re


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
    pass

if __name__ == "__main__":
    main()


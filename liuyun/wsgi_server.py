import os
from paste import httpserver
from paste.deploy import loadwsgi

def wrap_conf_type(f):
    def wrapper(conf_path, *args, **kwargs):
        if os.path.isdir(conf_path):
            conf_type = 'config_dir'
        else:
            conf_type = 'config'
        conf_uri = '%s:%s' % (conf_type, conf_path)
        return f(conf_uri,*args,**kwargs)
    return wrapper

loadapp = wrap_conf_type(loadwsgi.loadapp)


if __name__ == '__main__':
    config = '/home/liuyun/ly/swift/proxy-server.conf'
    app = loadapp(config)
    httpserver.serve(app)

import logging

class Terminal_App(object):
    def __init__(self,conf):
        pass

    def __call__(self,environ,start_response=None):
        if start_response is not None:
            start_response('200 OK',[('Content-Type','text/html')])
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s %(filename)s[line:%(lineno)d]%(levelname)s %(message)s',datefmt='%a, %d %b %Y %H:%M:%S',filename='myapp.log',filemode='w')
        logging.info('Hello Terminal!')
        return ['Hello Terminal!\n']


def app_factory(global_config,**local_conf):
    conf = global_config.copy()
    conf.update(local_conf)
    app = Terminal_App(conf)
    return app




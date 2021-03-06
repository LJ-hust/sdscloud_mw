import logging

class Pptv(object):
    def __init__(self,conf):
        pass

    def __call__(self,env,start_response=None):
        if start_response is not None:
            start_response('200 OK',[('Content-Type','text/html')])

        logger = logging.getLogger('pptvlogger')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler('test.log')
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s-%(name)s-%(levelname)s-%(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        logger.info('PPTV is really great!!')
        return ['PPTV is really great.!\n']

def app_factory(global_config, **local_conf):
    conf = global_config.copy()
    conf.update(local_conf)
    return Pptv(conf)

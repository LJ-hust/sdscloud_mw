

class HybridObjectController(BaseObjectController):

    server_type = 'Object'

    @public
    @cors_validation
    @delay_denial
    def PUT(self, req):
        if req.if_none_match:
            pass

        container_info = self.container_info(
                self.account_name, self.container_name, req)
        container_nodes = container_info['nodes']
        container_partition = container_info['partition']
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                      container_info['storage_policy'])

        #if we use single ring in the future, we can distinguish the local and cloud
        #from nodes' devs_info.
        local_object_ring, cloud_object_ring = self.app.get_object_ring(policy_index)
        local_partition, local_nodes = local_object_ring.get_nodes(        #
                self.account_name, self.container_name, self.object_name)  #
        cloud_partition, cloud_nodes = cloud_object_ring.get_nodes(        #
                self.account_name, self.container_name, self.object_name)  #

        #change headers, check
        ......

        source_header = req.headers.get('X-Copy-From')
        if source_header:
            pass
        else:
            reader = req.environ['wsgi.input'].read
            data_source = iter(lambda:reader(self.app.client_chunk_size), '')
            update_response = lambda req, resp: resp

        ......

        outgoing_headers = self._backend_requests(
                req, len(local_nodes)+len(cloud_nodes), container_partition,
                container_nodes,delete_at_container, delete_at_part,
                delete_at_nodes)

        resp = self._store_object(
                req, data_source, local_nodes+cloud_nodes, partition, outgoing_headers)
        return update_response(req, resp)

    def _backend_requests(self, req, n_outgoing,
                         container_partition, containers,
                         delete_at_container=None, delete_at_partition=None,
                         delete_at_nodes=None):
        #maybe I should add the correspond cloud to the headers for nodes.
        headers = [self.generate_request_headers(req, additional=req.headers)
                   for _junk in range(n_outgoing)]
        pass

    def _store_object(req):
        policy_index = int(req.headers.get('X-Backend-Storage-Policy-Index'))
        policy = POLICIES.get_by_index(policy_index)

        #I think hybrid type is 1, 2, 3 or 4, represent the rep_rep, rep_ec,
        #ec_rep, ec_ec respectively.
        hybrid_type = policy.hybrid_type

        local_min_conns = quorum_size()
        cloud_min_conns = quorum_size()

        #putters should be divided into local and cloud for check?
        putters = self._get_put_connections(......)

        try:
            #I prefer to check the putters for local and cloud together
            self._check_failure_put_connections(putters, req, nodes,
                    min_conns)

            #ec policy's parameters
            self._transfer_data()

            self._get_put_response()
        except HTTPException as resp:
            return resp

        resp = self.best_response()
        return resp


    def _transfer_data():
        if hybrid_type == 1:
            pass
        elif hybrid_type == 2:
            pass
        elif hybrid_type == 3:
            pass
        elif hybrid_type == 4:
            pass
        else:
            raise

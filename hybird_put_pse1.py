    def PUT(self, req):
	    obj_ring = self.app.get_object_ring(policy_index)
		partition, nodes_local,nodes_cloud = obj_ring.get_nodes(
            self.account_name, self.container_name, self.object_name)
			
		"""
		something about headers
		"""
		
		resp = self._store_object(
            req, data_source, nodes, partition, outgoing_headers)
		return update_response(req, resp)
		
		
    def _store_object(self, req, data_source, nodes, partition,
                      outgoing_headers):
		
		policy_index = req.headers.get('X-Backend-Storage-Policy-Index')
        policy = POLICIES.get_by_index(policy_index)
		
		####判断policy是哪一种,其中nodes_local和nodes_cloud通过nodes["name"]判断得来
		if replicas_replicas:
			nodes_replicas = nodes_local + nodes_cloud
		if ec42_ec42:
			nodes_ec42 = nodes_local + nodes_cloud
		if replicas_ec42:
			nodes_replicas = nodes_local
			nodes_ec42 = nodes_cloud
		if ec42_replicas:
		    nodes_replicas = nodes_cloud
			nodes_ec42 = nodes_local
        
		####存在nodes_replicas
		if nodes_replicas:
            # RFC2616:8.2.3 disallows 100-continue without a body
            if (req.content_length > 0) or req.is_chunked:
                expect_replicas = True
            else:
                expect_replicas = False
		    min_conns_replicas = quorum_size(len(nodes_replicas))
			
		if nodes_ec42:		
		    etag_hasher = md5()
			min_conns_ec42 = policy.quorum
		
		"""
		考虑到不同策略expert不同，将各node对应的expect，存入node[],_get_put_connections()中expect任意赋值
		"""
        connes, putters = self._get_put_connections(req, nodes, partition,
                                          outgoing_headers, policy, expect)
        
        try:
            # check that a minimum number of connections were established and
            # meet all the correct conditions set in the request
			"""
			通过len（conns）判断，因此考虑2个协程，否则重新设计min_conns
			"""
            self._check_failure_put_connections(conns, req, nodes_replicas, min_conns_replicas)
			self._check_failure_put_connections(putters, req, nodes_ec42, min_conns_ec42)
			# transfer data
			"""
			1考虑两个协程
			"""
            self._transfer_data_replica(req, data_source, conns, nodes_replicas)
			self._transfer_data_ec42(req, policy, data_source, putters,
                                nodes_ec42, min_conns_ec42, etag_hasher)
			"""
			2一个协程
			"""
			self._transfer_data(req, policy, data_source, conns,
                                nodes, min_conns_ec42, etag_hasher)
            # get responses
            statuses, reasons, bodies, etags = self._get_put_responses(
                req, conns, putters, nodes_replicas, nodes_ec42, final_phase,
				min_conns, need_quorum=need_quorum)
        except HTTPException as resp:
            return resp
			
	    ####  replicas部分
        finally:
            for conn in conns_replicas:
                conn.close()

        if len(etags_replicas) > 1:
            self.app.logger.error(
                _('Object servers returned %s mismatched etags'), len(etags_replicas))
            return HTTPServerError(request=req)
        etag_replicas = etags_replicas.pop() if len(etags_replicas) else None
			
	    #### ec42部分
		etag_ec42 = etag_hasher.hexdigest()
        
        #### 改写best_response这个函数，分别传入2种etag		
	    resp = self.best_response(req, statuses, reasons, bodies,
                        _('Object PUT'), etag_replicas = etag_replicas,etag_ec42 = ec42_ec42)
								  
        resp.last_modified = math.ceil(
            float(Timestamp(req.headers['X-Timestamp'])))
        return resp		
	
	
    def _get_put_connections(self, req, nodes, partition, outgoing_headers,
                             policy, expect):
        """
        Establish connections to storage nodes for PUT request
        """
        obj_ring = policy.object_ring
        node_iter = GreenthreadSafeIterator(
            self.iter_nodes_local_first(obj_ring, partition))
        pile = GreenPile(len(nodes))

        for nheaders in outgoing_headers:
            if expect:
                nheaders['Expect'] = '100-continue'
            pile.spawn(self._connect_put_node, node_iter, partition,
                       req.swift_entity_path, nheaders,
                       self.app.logger.thread_locals)

        conns = [conn for conn in pile if conn]

        return conns
		
		
    def _connect_put_node(self, node_iter, part, path, headers,
                          logger_thread_locals):
						  
						  
    def _transfer_data_replica(self, req, data_source, conns, nodes):
	def _transfer_data_ec42(self, req, policy, data_source, putters, nodes,
                       min_conns, etag_hasher):
					   

	def _get_put_responses(self, req, conns, putters, nodes_replicas, nodes_ec42, final_phase,
                           min_responses, need_quorum=True, **kwargs):
		pile1.spawn(self._get_conn_response_replica, conns, req)
		pile2.spawn(self._get_conn_response_ec42, putter, req,
                       final_phase=final_phase)

						   
    def _await_response_replica(self, conn, **kwargs):
    def _await_response_ec42(self, conn, final_phase):
	

	def _get_conn_response_replica(self, conn, req, **kwargs):
        resp = self._await_response(conn, **kwargs)
        return (conn, resp)
    def _get_conn_response_ec42(self, conn, req, final_phase, **kwargs):
	    resp = self._await_response(conn, final_phase=final_phase,
                                        **kwargs)
		return (conn, resp)				
#@ObjectControllerRouter.register(HYBIRD_POLICY)
class HybridObjectController(BaseObjectController):

    def _backend_requests(self, req, nodes,
                          container_partition, containers,
                          delete_at_container=None, delete_at_partition=None,
                          delete_at_nodes=None):
        n_outgoing = len(nodes)
        isc = self._is_cloud(nodes)

        headers = [self.generate_request_headers(req, additional=req.headers)
                   for _junk in range(n_outgoing)]
        for i, container in enumerate(containers):
            i = i % len(headers)

            headers[i]['X-Container-Partition'] = container_partition
            headers[i]['X-Container-Host'] = csv_append(
                headers[i].get('X-Container-Host'),
                '%(ip)s:%(port)s' % container)
            headers[i]['X-Container-Device'] = csv_append(
                headers[i].get('X-Container-Device'),
                container['device'])

        for i, node in enumerate(delete_at_nodes or []):
            i = i % len(headers)

            headers[i]['X-Delete-At-Container'] = delete_at_container
            headers[i]['X-Delete-At-Partition'] = delete_at_partition
            headers[i]['X-Delete-At-Host'] = csv_append(
                headers[i].get('X-Delete-At-Host'),
                '%(ip)s:%(port)s' % node)
            headers[i]['X-Delete-At-Device'] = csv_append(
                headers[i].get('X-Delete-At-Device'),
                node['device'])

        for i in range(n_outgoing):
            if isc[i] == False:
                headers[i]['X-Is-Cloud'] = False
                if (req.content_length > 0) or req.is_chunked:
                    headers[i]['Expect'] = '100-continue'
            if isc[i] == True:
                headers[i]['X-Is-Cloud'] = True
                headers[i]['Expect'] = '100-continue'

        return headers


    def _is_cloud(self,nodes):
        is_cloud = []
        for i, node in enumerate(nodes):
            if node['device'][0] == "c":
                is_cloud.append(True)
            else:
                is_cloud.append(False)

        return is_cloud


    def _check_failure_put_connections(self, conns, req, nodes, des, local_min_conns, cloud_min_conns):
        """
        Identify any failed connections and check minimum connection count.
        """

        if req.if_none_match is not None and '*' in req.if_none_match:
            statuses = [conn.resp.status for conn in conns if conn.resp]
            if HTTP_PRECONDITION_FAILED in statuses:
                # If we find any copy of the file, it shouldn't be uploaded
                self.app.logger.debug(
                    _('Object PUT returning 412, %(statuses)r'),
                    {'statuses': statuses})
                raise HTTPPreconditionFailed(request=req)

        if any(conn for conn in conns if conn.resp and
               conn.resp.status == HTTP_CONFLICT):
            timestamps = [HeaderKeyDict(conn.resp.getheaders()).get(
                'X-Backend-Timestamp') for conn in conns if conn.resp]
            self.app.logger.debug(
                _('Object PUT returning 202 for 409: '
                  '%(req_timestamp)s <= %(timestamps)r'),
                {'req_timestamp': req.timestamp.internal,
                 'timestamps': ', '.join(timestamps)})
            raise HTTPAccepted(request=req)

        self._check_min_conn(req, des, local_min_conns, cloud_min_conns)


    def _check_min_conn(self, req, des, local_min_conns, cloud_min_conns, msg=None):
        msg = msg or 'Object PUT returning 503, %(conns)s/%(nodes)s ' \
            'required connections'

        len_local = 0
        len_cloud = 0

        for len in des:
            if len == 'cloud':
                len_cloud = len_cloud + 1
            if len == 'local':
                len_local = len_local + 1

        if len_local < local_min_conns:
            self.app.logger.error((msg),
                                  {'conns': len_local, 'nodes': local_min_conns})
            raise HTTPServiceUnavailable(request=req)

        if len_cloud < cloud_min_conns:
            self.app.logger.error((msg),
                                  {'conns': len_cloud, 'nodes': cloud_min_conns})
            raise HTTPServiceUnavailable(request=req)


    def _get_put_connections(self, req, nodes, partition, outgoing_headers,
                             policy):

        """
        Establish connections to storage nodes for PUT request
        """
        des = []
        obj_ring = policy.object_ring
        # it is related to ring
        local_node_iter, cloud_node_iter = GreenthreadSafeIterator(
            self.iter_nodes_local_first(obj_ring, partition))
        pile = GreenPile(len(nodes))

        for nheaders in outgoing_headers:
            if nheaders['X-Is-Cloud']:
                pile.spawn(self._connect_put_cloud_node, cloud_node_iter, partition,
                            req.swift_entity_path, nheaders,
                            self.app.logger.thread_locals)
                des.append('cloud')
            else:
                pile.spawn(self._connect_put_local_node,local_node_iter, partition,
                            req.swift_entity_path, nheaders,
                            self.app.logger.thread_locals)
                des.append('local')

        conns = [conn for conn in pile if conn]

        return conns, des


    def _get_conn_response(self, conn, req, policy, final_phase=True, **kwargs):
        try:
            if policy = 'relica':
                resp = self._await_replica_response(conn, **kwargs)
            elif policy = 'ec':
                resp = self._await_ec_response(conn, final_phase=final_phase,
                                        **kwargs)
        except (Exception, Timeout):
            resp = None
            if final_phase:
                status_type = 'final'
            else:
                status_type = 'commit'
            self.app.exception_occurred(
                conn.node, _('Object'),
                _('Trying to get %s status of PUT to %s') % (
                    status_type, req.path))
        return (conn, resp)



    def _have_adequate_successes(self, statues, des, min_local_responses, min_cloud_responses):

        local_status = 0
        cloud_status = 0

        for i, s in enumerate(statues) if is_success(s):
            if des[i] == 'local':
                local_status += 1
            elif des[i] == 'cloud':
                cloud_status += 1

        if local_status >= min_local_responses and cloud_status >= min_cloud_responses:
            return True
        return False


    def _get_put_responses(self, req, conns, num_local_nodes, num_cloud_nodes, des, is_local_ec,
                           is_cloud_ec, local_final_phase, cloud_final_phase, min_local_responses,
                           min_cloud_responses, need_local_quorum=True, need_cloud_quorum=True):
        """
        Collect erasure coded object responses.

        Collect object responses to a PUT request and determine if
        satisfactory number of nodes have returned success.  Return
        statuses, quorum result if indicated by 'need_quorum' and
        etags if this is a final phase or a multiphase PUT transaction.

        :param req: the request
        :param putters: list of putters for the request
        :param num_nodes: number of nodes involved
        :param final_phase: boolean indicating if this is the last phase
        :param min_responses: minimum needed when not requiring quorum
        :param need_quorum: boolean indicating if quorum is required
        """
        statuses = []
        reasons = []
        bodies = []
        etags = set()
        policy_list = []

        # define the policy of cloud&local
        for add in des:
            if add == 'local' and is_local_ec == True:
                policy_list.append('ec')
            elif add == 'local' and is_local_ec == False:
                policy_list.append('replica')
            if add == 'cloud' and is_cloud_ec == True:
                policy_list.append('ec')
            if add == 'cloud' and is_cloud_ec == False:
                policy_list.append('replica')

        pile = GreenAsyncPile(len(conns))
        for i, conn in enumerate(conns):
            if conn.failed:
                continue
            if policy_list[i] == 'replica':
                pile.spawn(self._get_conn_response, conn, req, policy_list[i],
                            final_phase=True)
            elif policy_list[i] == 'ec' and des[i] == 'local':
                pile.spawn(self._get_conn_response, conn, req, policy_list[i],
                            final_phase=local_final_phase)
            elif policy_list[i] == 'ec' and des[i] == 'cloud':
                pile.spawn(self._get_conn_response, conn, req, policy_list[i],
                            final_phase=cloud_final_phase)

        def _handle_response(conn, response, final_phase=False):
            statuses.append(response.status)
            reasons.append(response.reason)
            if final_phase:
                body = response.read()
                bodies.append(body)
            else:
                body = ''
            if response.status == HTTP_INSUFFICIENT_STORAGE:
                conn.failed = True
                self.app.error_limit(conn.node,
                                     _('ERROR Insufficient Storage'))
            elif response.status >= HTTP_INTERNAL_SERVER_ERROR:
                conn.failed = True
                self.app.error_occurred(
                    conn.node,
                    _('ERROR %(status)d %(body)s From Object Server '
                      're: %(path)s') %
                    {'status': response.status,
                     'body': body[:1024], 'path': req.path})
            elif is_success(response.status):
                etags.add(response.getheader('etag').strip('"'))

        quorum = False
        for i, (conn, response) in enumerate(pile):
            if response:
                if policy_list[i] == 'ec' and des[i] == 'local':
                    _handle_response(conn, response, local_final_phase)
                elif policy_list[i] == 'ec' and des[i] == 'cloud':
                    _handle_response(conn, response, cloud_final_phase)
                else:
                    _handle_response(conn, response, True)
                """????"""
                if self._have_adequate_successes(statuses, min_local_responses,
                                                 min_cloud_responses):
                    break
            else:
                conn.failed = True

        # give any pending requests *some* chance to finish
        finished_quickly = pile.waitall(self.app.post_quorum_timeout)
        for i, (conn, response) in enumerate(finished_quickly):
            if response:
                if policy_list[i] == 'ec' and des[i] == 'local':
                    _handle_response(conn, response, local_final_phase)
                elif policy_list[i] == 'ec' and des[i] == 'cloud':
                    _handle_response(conn, response, cloud_final_phase)
                else:
                    _handle_response(conn, response, True)

        local_statuses = 0
        cloud_statuses = 0
        for i, s in enumerate(statues):
            if des[i] == 'local':
                local_statuses += 1
            elif des[i] == 'cloud':
                cloud_statuses += 1

        if need_local_quorum and is_local_ec:
            if local_final_phase:
                while len(local_statuses) < num_local_nodes:
                    statuses.append(HTTP_SERVICE_UNAVAILABLE)
                    reasons.append('')
                    bodies.append('')
            else:
                # intermediate response phase - set return value to true only
                # if there are enough 100-continue acknowledgementsi
                if self.have_quorum(local_statuses, num_local_nodes):
                    quorum = True

        if need_cloud_quorum and is_cloud_ec:
            if cloud_final_phase:
                while len(cloud_statuses) < num_cloud_nodes:
                    statuses.append(HTTP_SERVICE_UNAVAILABLE)
                    reasons.append('')
                    bodies.append('')
            else:
                # intermediate response phase - set return value to true only
                # if there are enough 100-continue acknowledgementsi
                if self.have_quorum(cloud_statuses, num_cloud_nodes):
                    quorum = True

        if not is_local_ec:
            while len(local_statuses) < num_local_nodes:
                statuses.append(HTTP_SERVICE_UNAVAILABLE)
                reasons.append('')
                bodies.append('')

        if not is_cloud_ec:
            while len(cloud_statuses) < num_cloud_nodes:
                statuses.append(HTTP_SERVICE_UNAVAILABLE)
                reasons.append('')
                bodies.append('')

        return statuses, reasons, bodies, etags, quorum


    def _transfer_data(self, ...):

        # all replicas
        if hybrid_type == 1:
            _transfer_data_replica(local_nodes + cloud_nodes)
        # the local uses the policy of replicas, the cloud use ec
        elif hybrid_type == 2:
            _transfer_data_replica(local_nodes)
            _transfer_data_ec(cloud_nodes)
        # the cloud uses the policy of replicas, the local use ec
        elif hybrid_type == 3:
            _transfer_data_replica(cloud_nodes)
            _transfer_data_ec(local_nodes)
        # all ec
        elif hybrid_type == 4:
            _transfer_data_ec(local_nodes)
            _transfer_data_ec(cloud_nodes)


    def _store_object(self, req, data_source, local_nodes, cloud_nodes, partition,
                      outgoing_headers):
        """
        Store an erasure coded object.
        """
        policy_index = int(req.headers.get('X-Backend-Storage-Policy-Index'))
        policy = POLICIES.get_by_index(policy_index)
        # Since the request body sent from client -> proxy is not
        # the same as the request body sent proxy -> object, we
        # can't rely on the object-server to do the etag checking -
        # so we have to do it here.
        etag_hasher = md5()
        nodes = local_nodes + cloud_nodes
        ####
        min_local_conns,min_cloud_conns = policy.quorum


        conns, des = self._get_put_connections(req, nodes, partition,
                                               outgoing_headers,policy)
        try:
            # check that a minimum number of connections were established and
            # meet all the correct conditions set in the request
            self._check_failure_put_connections(conns, des, req, nodes,
                                                min_local_conns, min_cloud_conns)

            self._transfer_data(req, policy, data_source, putters,
                                nodes, min_conns, etag_hasher)

            if is_local_ec:
                local_final_phase = True
                need_local_quorum = False
                min_local_resp = 2
            else:
                local_final_phase = ???
                min_local_resp =?

            if is_cloud_ec:
                cloud_final_phase = True
                need_cloud_quorum = False
                min_cloud_resp = 2
            else:
                cloud_final_phase = ???
                min_cloud_resp =?

            conns = [conn for conn in conns if not conn.failed]

            # ignore response etags, and quorum boolean
            statuses, reasons, bodies, _etags, _quorum = \
                self._get_put_responses(req, conns, len(local_nodes), len(cloud_nodes),
                                        des, is_local_ec, is_cloud_ec,
                                        local_final_phase, cloud_final_phase,
                                        min_local_resp, min_cloud_resp,
                                        need_local_quorum, nees_cloud_quorum)

            #test by lijing
            self.app.logger.info('statuses:')
            self.app.logger.info(statuses)
            self.app.logger.info('reasons:')
            self.app.logger.info(reasons)
            self.app.logger.info('bodies:')
            self.app.logger.info(bodies)
            self.app.logger.info('etags:')
            self.app.logger.info(_etags)
            self.app.logger.info('_quorum:')
            self.app.logger.info(_quorum)

        except HTTPException as resp:
            return resp
        finally:
            for conn in conns:
                conn.close()

        """etag = etag_hasher.hexdigest()
        #test by lijing
        self.app.logger.info(etag)"""

        ####


        if is_local_ec:
            etag_local = etag_hasher_l.hexdigest()
        else:
            etag_local = '...'
        if is_cloud_ec:
            etag_cloud = etag_hasher_c.hexdigest()
        else:
            etag_cloud = '...'


        resp = self.best_response(req, statuses, reasons, bodies,
                                  _('Object PUT'), etag=etag,
                                  quorum_size=min_local_conns+min_cloud_conns)

        self.app.logger.info('~~~')
        self.app.logger.info(resp.headers)

        resp.last_modified = math.ceil(
            float(Timestamp(req.headers['X-Timestamp'])))

        self.app.logger.info('~~~')
        self.app.logger.info(resp.headers)
        return resp




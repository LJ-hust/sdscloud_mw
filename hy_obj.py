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


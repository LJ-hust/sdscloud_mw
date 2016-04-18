# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ConfigParser import ConfigParser
import textwrap
import string

from swift.common.utils import config_true_value, SWIFT_CONF_FILE
from swift.common.ring import Ring
from swift.common.utils import quorum_size
from swift.common.exceptions import RingValidationError
from pyeclib.ec_iface import ECDriver, ECDriverError, VALID_EC_TYPES

LEGACY_POLICY_NAME = 'Policy-0'
VALID_CHARS = '-' + string.letters + string.digits
VALID_HYBRID_TYPES = ['ec_ec', 'ec_rep', 'rep_rep', 'rep_ec']

DEFAULT_POLICY_TYPE = REPL_POLICY = 'replication'
EC_POLICY = 'erasure_coding'
HYBRID_POLICY = 'hybrid'
DEFAULT_EC_OBJECT_SEGMENT_SIZE = 1048576
CLOUD_EC_OBJECT_SEGMENT_SIZE = 1048576

class PolicyError(ValueError):

    def __init__(self, msg, index=None):
        if index is not None:
            msg += ', for index %r' % index
        super(PolicyError, self).__init__(msg)


def _get_policy_string(base, policy_index):
    if policy_index == 0 or policy_index is None:
        return_string = base
    else:
        return_string = base + "-%d" % int(policy_index)
    return return_string


def get_policy_string(base, policy_or_index):
    """
    Helper function to construct a string from a base and the policy.
    Used to encode the policy index into either a file name or a
    directory name by various modules.

    :param base: the base string
    :param policy_or_index: StoragePolicy instance, or an index
                            (string or int), if None the legacy
                            storage Policy-0 is assumed.

    :returns: base name with policy index added
    :raises: PolicyError if no policy exists with the given policy_index
    """
    if isinstance(policy_or_index, BaseStoragePolicy):
        policy = policy_or_index
    else:
        policy = POLICIES.get_by_index(policy_or_index)
        if policy is None:
            raise PolicyError("Unknown policy", index=policy_or_index)
    return _get_policy_string(base, int(policy))


def split_policy_string(policy_string):
    """
    Helper function to convert a string representing a base and a
    policy.  Used to decode the policy from either a file name or
    a directory name by various modules.

    :param policy_string: base name with policy index added

    :raises: PolicyError if given index does not map to a valid policy
    :returns: a tuple, in the form (base, policy) where base is the base
              string and policy is the StoragePolicy instance for the
              index encoded in the policy_string.
    """
    if '-' in policy_string:
        base, policy_index = policy_string.rsplit('-', 1)
    else:
        base, policy_index = policy_string, None
    policy = POLICIES.get_by_index(policy_index)
    if get_policy_string(base, policy) != policy_string:
        raise PolicyError("Unknown policy", index=policy_index)
    return base, policy


class BaseStoragePolicy(object):
    """
    Represents a storage policy.  Not meant to be instantiated directly;
    implement a derived subclasses (e.g. StoragePolicy, ECStoragePolicy, etc)
    or use :func:`~swift.common.storage_policy.reload_storage_policies` to
    load POLICIES from ``swift.conf``.

    The object_ring property is lazy loaded once the service's ``swift_dir``
    is known via :meth:`~StoragePolicyCollection.get_object_ring`, but it may
    be over-ridden via object_ring kwarg at create time for testing or
    actively loaded with :meth:`~StoragePolicy.load_ring`.
    """

    policy_type_to_policy_cls = {}

    def __init__(self, idx, name='', is_default=False, is_deprecated=False,
                 object_ring=None):
        # do not allow BaseStoragePolicy class to be instantiated directly
        if type(self) == BaseStoragePolicy:
            raise TypeError("Can't instantiate BaseStoragePolicy directly")
        # policy parameter validation
        try:
            self.idx = int(idx)
        except ValueError:
            raise PolicyError('Invalid index', idx)
        if self.idx < 0:
            raise PolicyError('Invalid index', idx)
        if not name:
            raise PolicyError('Invalid name %r' % name, idx)
        # this is defensively restrictive, but could be expanded in the future
        if not all(c in VALID_CHARS for c in name):
            raise PolicyError('Names are used as HTTP headers, and can not '
                              'reliably contain any characters not in %r. '
                              'Invalid name %r' % (VALID_CHARS, name))
        if name.upper() == LEGACY_POLICY_NAME.upper() and self.idx != 0:
            msg = 'The name %s is reserved for policy index 0. ' \
                'Invalid name %r' % (LEGACY_POLICY_NAME, name)
            raise PolicyError(msg, idx)
        self.name = name
        self.is_deprecated = config_true_value(is_deprecated)
        self.is_default = config_true_value(is_default)
        if self.policy_type not in BaseStoragePolicy.policy_type_to_policy_cls:
            raise PolicyError('Invalid type', self.policy_type)
        if self.is_deprecated and self.is_default:
            raise PolicyError('Deprecated policy can not be default.  '
                              'Invalid config', self.idx)
        self.ring_name = _get_policy_string('object', self.idx)
        self.object_ring = object_ring

    def __int__(self):
        return self.idx

    def __cmp__(self, other):
        return cmp(self.idx, int(other))

    def __repr__(self):
        return ("%s(%d, %r, is_default=%s, "
                "is_deprecated=%s, policy_type=%r)") % \
            (self.__class__.__name__, self.idx, self.name,
             self.is_default, self.is_deprecated, self.policy_type)

    @classmethod
    def register(cls, policy_type):
        """
        Decorator for Storage Policy implementations to register
        their StoragePolicy class.  This will also set the policy_type
        attribute on the registered implementation.
        """
        def register_wrapper(policy_cls):
            if policy_type in cls.policy_type_to_policy_cls:
                raise PolicyError(
                    '%r is already registered for the policy_type %r' % (
                        cls.policy_type_to_policy_cls[policy_type],
                        policy_type))
            cls.policy_type_to_policy_cls[policy_type] = policy_cls
            policy_cls.policy_type = policy_type
            return policy_cls
        return register_wrapper

    @classmethod
    def _config_options_map(cls):
        """
        Map config option name to StoragePolicy parameter name.
        """
        return {
            'name': 'name',
            'policy_type': 'policy_type',
            'default': 'is_default',
            'deprecated': 'is_deprecated',
        }

    @classmethod
    def from_config(cls, policy_index, options):
        config_to_policy_option_map = cls._config_options_map()
        policy_options = {}
        for config_option, value in options.items():
            try:
                policy_option = config_to_policy_option_map[config_option]
            except KeyError:
                raise PolicyError('Invalid option %r in '
                                  'storage-policy section' % config_option,
                                  index=policy_index)
            policy_options[policy_option] = value
        return cls(policy_index, **policy_options)

    def get_info(self, config=False):
        """
        Return the info dict and conf file options for this policy.

        :param config: boolean, if True all config options are returned
        """
        info = {}
        for config_option, policy_attribute in \
                self._config_options_map().items():
            info[config_option] = getattr(self, policy_attribute)
        if not config:
            # remove some options for public consumption
            if not self.is_default:
                info.pop('default')
            if not self.is_deprecated:
                info.pop('deprecated')
            info.pop('policy_type')
        return info

    def _validate_ring(self):
        """
        Hook, called when the ring is loaded.  Can be used to
        validate the ring against the StoragePolicy configuration.
        """
        pass

    def load_ring(self, swift_dir):
        """
        Load the ring for this policy immediately.

        :param swift_dir: path to rings
        """
        if self.object_ring:
            return
        self.object_ring = Ring(swift_dir, ring_name=self.ring_name)

        # Validate ring to make sure it conforms to policy requirements
        self._validate_ring()

    @property
    def quorum(self):
        """
        Number of successful backend requests needed for the proxy to
        consider the client request successful.
        """
        raise NotImplementedError()


@BaseStoragePolicy.register(REPL_POLICY)
class StoragePolicy(BaseStoragePolicy):
    """
    Represents a storage policy of type 'replication'.  Default storage policy
    class unless otherwise overridden from swift.conf.

    Not meant to be instantiated directly; use
    :func:`~swift.common.storage_policy.reload_storage_policies` to load
    POLICIES from ``swift.conf``.
    """

    @property
    def quorum(self):
        """
        Quorum concept in the replication case:
            floor(number of replica / 2) + 1
        """
        if not self.object_ring:
            raise PolicyError('Ring is not loaded')
        return quorum_size(self.object_ring.replica_count)


@BaseStoragePolicy.register(HYBRID_POLICY)
class HybridStoragePolicy(BaseStoragePolicy):
    """
    Represents a storage policy of type 'hybrid'.

    Not meant to be instantiated directly; use
    :func:`~swift.common.storage_policy.reload_storage_policies` to load
    POLICIES from ``swift.conf``.
    """
    def __init__(self, idx, name='', is_default=False,is_deprecated=False,
            object_ring=None,local_ec_segment_size=DEFAULT_EC_OBJECT_SEGMENT_SIZE,
            cloud_ec_segment_size=CLOUD_EC_OBJECT_SEGMENT_SIZE,
            hybrid_type=None, local_ec_type=None, cloud_ec_type=None,
            local_repl_num=None, cloud_repl_num=None,
            local_ec_ndata=None, local_ec_nparity=None,
            cloud_ec_ndata=None, cloud_ec_nparity=None):
	super(HybridStoragePolicy, self).__init__(
                idx, name, is_default, is_deprecated, object_ring)

        # Validate hybrid policy specific members
        # hybrid_type must in rep_ec, ec_rep, rep_rep, ec_ec
	if hybrid_type is None:
            raise PolicyError('Missing hybrid_type')
        if hybrid_type not in VALID_HYBRID_TYPES:
            raise PolicyError('Wrong hybrid_type %s for policy %s, should be one'
                    'of "%s"' % (hybrid_type, self.name, ','.join(VALID_HYBRID_TYPES)))
	self._hybrid_type = hybrid_type


        #Validate erasure_coding policy specific members
        #local_ec_type is one of the EC implementations supported by PyEClib
        def valid_local_ec_type(local_ec_type):
            if local_ec_type is None:
                raise PolicyError('Missing local_ec_type')
            if local_ec_type not in VALID_EC_TYPES:
                raise PolicyError('Wrong local_ec_type %s for policy %s, should be one'
                        ' of "%s"' % (local_ec_type, self.name,
                            ', '.join(VALID_EC_TYPES)))
            self._local_ec_type = local_ec_type

        #Validate erasure_coding policy specific members
        #cloud_ec_type is one of the EC implementations supported by PyEClib
        def valid_cloud_ec_type(cloud_ec_type):
            if cloud_ec_type is None:
                raise PolicyError('Missing cloud_ec_type')
            if cloud_ec_type not in VALID_EC_TYPES:
                raise PolicyError('Wrong cloud_ec_type %s for policy %s, should be one'
                        ' of "%s"' % (cloud_ec_type, self.name,
                            ', '.join(VALID_EC_TYPES)))
            self._cloud_ec_type = cloud_ec_type

        #Define _local_repl_num as the number of replicate in local
        #Accessible as the property "local_repl_num"
        def valid_local_repl_num(local_repl_num):
            try:
                value = int(local_repl_num)
                if value <= 0:
                    raise PolicyError('Invalid local_repl_num')
                self._local_repl_num = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid local_repl_num %r' %
                        local_repl_num, index=self.idx )

        #Define _cloud_repl_num as the number of replicate in clouds
        #Accessible as the property "cloud_repl_num"
        def valid_cloud_repl_num(cloud_repl_num):
            try:
                value = int(cloud_repl_num)
                if value <= 0:
                    raise PolicyError('Invalid cloud_repl_num')
                self._cloud_repl_num = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid cloud_repl_num %r' %
                        cloud_repl_num, index=self.idx)

        #Define _local_ec_ndata as the number of EC data fragments in local
        #Accessible as the property "local_ec_ndata"
        def valid_local_ec_ndata(local_ec_ndata):
            try:
                value = int(local_ec_ndata)
                if value <= 0:
                    raise ValueError
                self._local_ec_ndata = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid local_ec_num_data_fragments %r' %
                        local_ec_ndata, index=self.idx)

        #Define _local_ec_nparity as the number of EC parity fragments in local
        #Accessible as the property "local_ec_nparity"
        def valid_local_ec_nparity(local_ec_nparity):
            try:
                value = int(local_ec_nparity)
                if value <= 0:
                    raise ValueError
                self._local_ec_nparity = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid local_ec_num_parity_fragments %r' %
                        local_ec_nparity, index=self.idx)

	# Define _cloud_ec_ndata as the number of EC data fragments in clouds
        # Accessible as the property "cloud_ec_ndata"
        def valid_cloud_ec_ndata(cloud_ec_ndata):
            try:
                value = int(cloud_ec_ndata)
                if value <= 0:
                    raise ValueError
                self._cloud_ec_ndata = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid cloud_ec_num_data_fragments %r' %
                        cloud_ec_ndata, index=self.idx)

	# Define _cloud_ec_nparity as the number of EC parity fragments in clouds
        # Accessible as the property "cloud_ec_nparity"
        def valid_cloud_ec_nparity(cloud_ec_nparity):
            try:
                value = int(cloud_ec_nparity)
                if value <= 0:
                    raise ValueError
                self._cloud_ec_nparity = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid cloud_ec_num_parity_fragments %r' %
                        cloud_ec_nparity, index=self.idx)

	# Define _local_ec_segment_size as the encode segment unit size
        # Accessible as the property "local_ec_segment_size"
        def valid_local_ec_segment_size(local_ec_segment_size):
            try:
                value = int(local_ec_segment_size)
                if value <= 0:
                    raise ValueError
                self._local_ec_segment_size = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid local_ec_object_segment_size %r' %
                       local_ec_segment_size, index=self.idx)

        # Define _cloud_ec_segment_size as the encode segment unit size
        # Accessible as the property "cloud_ec_segment_size"
        def valid_cloud_ec_segment_size(cloud_ec_segment_size):
            try:
                value = int(cloud_ec_segment_size)
                if value <= 0:
                    raise ValueError
                self._cloud_ec_segment_size = value
            except (TypeError, ValueError):
                raise PolicyError('Invalid cloud_ec_objec_segment_size %d' %
                        cloud_ec_segment_size, index=self.idx)

        def valid_and_return_policy():
            if hybrid_type == 'rep_ec':
                valid_cloud_ec_type(cloud_ec_type)
                valid_local_repl_num(local_repl_num)
                valid_cloud_ec_ndata(cloud_ec_ndata)
                valid_cloud_ec_nparity(cloud_ec_nparity)
                valid_cloud_ec_segment_size(cloud_ec_segment_size)
                local = StoragePolicy(idx, name, is_default, is_deprecated, object_ring)
                cloud = ECStoragePolicy(idx, name, is_default, is_deprecated, object_ring,
                        cloud_ec_segment_size, cloud_ec_type, cloud_ec_ndata, cloud_ec_nparity)
                return local, cloud
            if hybrid_type == 'ec_rep':
                valid_local_ec_type(local_ec_type)
                valid_local_ec_ndata(local_ec_ndata)
                valid_local_ec_nparity(local_ec_nparity)
                valid_cloud_repl_num(cloud_repl_num)
                valid_local_ec_segment_size(local_ec_segment_size)
                local = ECStoragePolicy(idx, name, is_default, is_deprecated, object_ring,
                        local_ec_segment_size, local_ec_type, local_ec_ndata, local_ec_nparity)
                cloud = StoragePolicy(idx, name, is_default, is_deprecated, object_ring)
                return local, cloud
            if hybrid_type =='rep_rep':
                valid_local_repl_num(local_repl_num)
                valid_cloud_repl_num(cloud_repl_num)
                local = StoragePolicy(idx, name, is_default, is_deprecated, object_ring)
                cloud = StoragePolicy(idx, name, is_default, is_deprecated, object_ring)
                return local, cloud
            if hybrid_type == 'ec_ec':
                valid_local_ec_type(local_ec_type)
                valid_cloud_ec_type(cloud_ec_type)
                valid_local_ec_ndata(local_ec_ndata)
                valid_local_ec_nparity(local_ec_nparity)
                valid_cloud_ec_ndata(cloud_ec_ndata)
                valid_cloud_ec_nparity(cloud_ec_nparity)
                valid_local_ec_segment_size(local_ec_segment_size)
                valid_cloud_ec_segment_size(cloud_ec_segment_size)
                local = ECStoragePolicy(idx, name, is_default, is_deprecated, object_ring,
                        local_ec_segment_size, local_ec_type, local_ec_ndata, local_ec_nparity)
                cloud = ECStoragePolicy(idx, name, is_default, is_deprecated, object_ring,
                        cloud_ec_segment_size, cloud_ec_type, cloud_ec_ndata, cloud_ec_nparity)
                return local, cloud
        self._local_policy, self._cloud_policy = valid_and_return_policy()

    @property
    def hybrid_type(self):
	return self._hybrid_type

    @property
    def get_local_policy(self):
        return self._local_policy

    @property
    def get_cloud_policy(self):
        return self._cloud_policy

    @property
    def local_ec_type(self):
        return self._local_ec_type

    @property
    def cloud_ec_type(self):
        return self._cloud_ec_type

    @property
    def local_repl_num(self):
	return self._local_repl_num

    @property
    def cloud_repl_num(self):
        return self._cloud_repl_num

    @property
    def local_ec_ndata(self):
        return self._local_ec_ndata

    @property
    def cloud_ec_ndata(self):
	return self._cloud_ec_ndata

    @property
    def local_ec_nparity(self):
        return self._local_ec_nparity

    @property
    def cloud_ec_nparity(self):
	return self._cloud_ec_nparity

    @property
    def local_ec_segment_size(self):
	return self._local_ec_segment_size

    @property
    def cloud_ec_segment_size(self):
        return self._cloud_ec_segment_size

    @property
    def local_fragment_size(self):
        if self._hybrid_type == 'ec_ec' or self._hybrid_type == 'ec_rep':
            return self._local_policy.fragment_size

    @property
    def cloud_fragment_size(self):
        if self._hybrid_type == 'ec_ec' or self._hybrid_type == 'rep_ec':
            return self._cloud_policy.fragment_size

    @property
    def hybrid_scheme_description(self):
        if self._hybrid_type == 'rep_ec':
            return "%s %d+%d+%d" % (self._hybrid_type, self._local_repl_num,
                    self._cloud_ec_ndata, self._cloud_ec_nparity)
        if self._hybrid_type == 'ec_rep':
            return "%s %d+%d+%d" % (self._hybrid_type, self._local_ec_ndata,
                    self._local_ec_nparity, self._cloud_repl_num)
        if self._hybrid_type == 'rep_rep':
            return "%s %d+%d" % (self._hybrid_type, self._local_repl_num,
                    self._cloud_repl_num)
        if self._hybrid_type == 'ec_ec':
            return "%s %d+%d+%d+%d" % (self._hybrid_type,
                    self._local_ec_ndata, self._local_ec_nparity,
                    self._cloud_ec_ndata, self._cloud_ec_nparity)

    def __repr__(self):
        if self._hybrid_type == 'rep_ec':
            return ("%s, HYBRID config(hybrid_type=%s, local_repl_num=%d, cloud_ec_type=%s, "
            "cloud_ec_segment_size=%d, cloud_ec_ndata=%d, cloud_ec_nparity=%d)") % (
                    super(HybridStoragePolicy, self).__repr__(), self.hybrid_type,
                    self.local_repl_num, self.cloud_ec_type, self.cloud_ec_segment_size,
                    self.cloud_ec_ndata, self.cloud_ec_nparity)
        if self._hybrid_type == 'ec_rep':
            return ("%s, HYBRID config(hybrid_type=%s, local_ec_type=%s,local_ec_segment_size=%d, "
            "local_ec_ndata=%d, local_ec_nparity=%d, cloud_repl_num=%d)") % (
                    super(HybridStoragePolicy, self).__repr__(), self.hybrid_type,
                    self.local_ec_type, self.local_ec_segment_size, self.local_ec_ndata,
                    self.local_ec_nparity, self.cloud_repl_num)
        if self._hybrid_type == 'rep_rep':
            return ("%s, HYBRID config(hybrid_type=%s, local_repl_num=%d, cloud_repl_num=%d)") % (
                    super(HybridStoragePolicy, self).__repr__(), self.hybrid_type,
                    self.local_repl_num, self.cloud_repl_num)
        if self._hybrid_type == 'ec_ec':
            return ("%s, HYBRID config(hybrid_type=%s, local_ec_type=%s, local_ec_segment_size=%d, "
                    "local_ec_ndata=%d, local_ec_nparity=%d, cloud_ec_type=%s, "
                    "cloud_ec_segment_size=%d, cloud_ec_ndata=%d, cloud_ec_nparity=%d)") % (
                    super(HybridStoragePolicy, self).__repr__(), self.hybrid_type,
                    self.local_ec_type, self.local_ec_segment_size, self.local_ec_ndata, self.local_ec_nparity,
                    self.cloud_ec_type, self.cloud_ec_segment_size, self.cloud_ec_ndata, self.cloud_ec_nparity)

    @classmethod
    def _config_options_map(cls, hy_type):
	options = super(HybridStoragePolicy, cls)._config_options_map()
        if hy_type == 'rep_ec':
            options.update({
                'hybrid_type': 'hybrid_type',
                'cloud_ec_object_segment_size': 'cloud_ec_segment_size',
                'cloud_ec_type': 'cloud_ec_type',
                'local_replica_num': 'local_repl_num',
                'cloud_ec_num_data_fragments': 'cloud_ec_ndata',
                'cloud_ec_num_parity_fragments': 'cloud_ec_nparity',
            })
        if hy_type == 'ec_rep':
            options.update({
                'hybrid_type': 'hybrid_type',
                'local_ec_object_segment_size': 'local_ec_segment_size',
                'local_ec_type': 'local_ec_type',
                'cloud_replica_num': 'cloud_repl_num',
                'local_ec_num_data_fragments': 'local_ec_ndata',
                'local_ec_num_parity_fragments': 'local_ec_nparity',
            })
        if hy_type == 'rep_rep':
            options.update({
                'hybrid_type': 'hybrid_type',
                'local_replica_num': 'local_repl_num',
                'cloud_replica_num': 'cloud_repl_num',
            })
        if hy_type == 'ec_ec':
            options.update({
                'hybrid_type': 'hybrid_type',
                'local_ec_object_segment_size': 'local_ec_segment_size',
                'cloud_ec_object_segment_size': 'cloud_ec_segment_size',
                'local_ec_type': 'local_ec_type',
                'cloud_ec_type': 'cloud_ec_type',
                'local_ec_num_data_fragments': 'local_ec_ndata',
                'local_ec_num_parity_fragments': 'local_ec_nparity',
                'cloud_ec_num_data_fragments': 'cloud_ec_ndata',
                'cloud_ec_num_parity_fragments': 'cloud_ec_nparity',
            })
	return options

    @classmethod
    def from_config(cls, policy_index, options):
        hy_type = options['hybrid_type']
        config_to_policy_option_map = cls._config_options_map(hy_type)
        policy_options = {}
        for config_option, value in options.items():
            try:
                policy_option = config_to_policy_option_map[config_option]
            except KeyError:
                raise PolicyError('Invalid option %r in '
                        'storage-policy section' % config_option, index=policy_index)
            policy_options[policy_option] = value
        return cls(policy_index, **policy_options)

    def get_info(self, config=False):
	#info = super(HybridStoragePolicy, self).get_info(config=config)
	info = {}
        for config_option, policy_attribute in self._config_options_map(self._hybrid_type).items():
            info[config_option] = getattr(self, policy_attribute)

        if not config:
            if not self.is_default:
                info.pop('default')
            if not self.is_deprecated:
                info.pop('deprecated')
            info.pop('policy_type')
            if self._hybrid_type == 'rep_ec':
                info.pop('local_replica_num')
                info.pop('cloud_ec_object_segment_size')
                info.pop('cloud_ec_num_data_fragments')
                info.pop('cloud_ec_num_parity_fragments')
                info.pop('cloud_ec_type')
                info.pop('hybrid_type')
            if self._hybrid_type == 'ec_rep':
                info.pop('local_ec_object_segment_size')
                info.pop('local_ec_num_data_fragments')
                info.pop('local_ec_num_parity_fragments')
                info.pop('cloud_replica_num')
                info.pop('local_ec_type')
                info.pop('hybrid_type')
            if self._hybrid_type == 'rep_rep':
                info.pop('local_replica_num')
                info.pop('cloud_replica_num')
                info.pop('hybrid_type')
            if self._hybrid_type == 'ec_ec':
                info.pop('local_ec_object_segment_size')
                info.pop('local_ec_num_data_fragments')
                info.pop('local_ec_num_parity_fragments')
                info.pop('cloud_ec_object_segment_size')
                info.pop('cloud_ec_num_data_fragments')
                info.pop('cloud_ec_num_parity_fragments')
                info.pop('local_ec_type')
                info.pop('cloud_ec_type')
                info.pop('hybrid_type')
	return info

    def _validate_ring(self):
        """
        EC specific Validation

        Replica count check - we need _at_least_ (#data + #parity) replicas
        configured. Also if the replica count is larger than exactly that
        number there's a non-zero risk of error for code that is considering
        the num of nodes in the primary list from the ring.
        """
        if not self.object_ring:
            raise PolicyError('Ring is not loaded')
        nodes_configured = self.object_ring.replica_count
        if self._hybrid_type == 'rep_ec' and nodes_configured != (
            self.local_repl_num + self.cloud_ec_ndata + self.cloud_ec_nparity):
            raise RingValidationError(
                    'EC ring for policy %s needs to be configured with '
                    'exactly %d nodes. Got %d.' % (self.name,
                    self.local_repl_num + self.cloud_ec_ndata + self.cloud_ec_nparity,
                    nodes_configured))
        if self._hybrid_type == 'ec_rep' and nodes_configured != (
                self.local_ec_ndata + self.local_ec_nparity + self.cloud_repl_num):
            raise RingValidationError(
                    'EC ring for policy %s needs to be configured with '
                    'exactly %d nodes. Got %d.' % (self.name,
                    self.local_ec_ndata + self.local_ec_nparity + self.cloud_repl_num,
                    nodes_configured))
        if self._hybrid_type == 'rep_rep' and nodes_configured != (
                self.local_repl_num + self.cloud_repl_num):
            raise RingValidationError(
                    'EC ring for policy %s need to be configured with exactly %d nodes. Got %d.' % (
                        self.name, self.local_repl_num + self.cloud_repl_num, nodes_configured))
        if self._hybrid_type == 'ec_ec' and nodes_configured != (
                self.local_ec_ndata + self.local_ec_nparity + self.cloud_ec_ndata + self.cloud_ec_nparity):
            raise RingValidationError(
                    'EC ring for policy %s needs to be configured with exactly %d nodes. Got %d.' % (
                    self.name, self.local_ec_ndata + self.local_ec_nparity + self.cloud_ec_ndata + self.cloud_ec_nparity,
                    nodes_configured))

    @property
    def quorum(self):
        return self._local_policy.quorum(), self._cloud_policy.quorum()


@BaseStoragePolicy.register(EC_POLICY)
class ECStoragePolicy(BaseStoragePolicy):
    """
    Represents a storage policy of type 'erasure_coding'.

    Not meant to be instantiated directly; use
    :func:`~swift.common.storage_policy.reload_storage_policies` to load
    POLICIES from ``swift.conf``.
    """
    def __init__(self, idx, name='', is_default=False,
                 is_deprecated=False, object_ring=None,
                 ec_segment_size=DEFAULT_EC_OBJECT_SEGMENT_SIZE,
                 ec_type=None, ec_ndata=None, ec_nparity=None):
        super(ECStoragePolicy, self).__init__(
            idx, name, is_default, is_deprecated, object_ring)

        # Validate erasure_coding policy specific members
        # ec_type is one of the EC implementations supported by PyEClib
        if ec_type is None:
            raise PolicyError('Missing ec_type')
        if ec_type not in VALID_EC_TYPES:
            raise PolicyError('Wrong ec_type %s for policy %s, should be one'
                              ' of "%s"' % (ec_type, self.name,
                              ', '.join(VALID_EC_TYPES)))
        self._ec_type = ec_type

        # Define _ec_ndata as the number of EC data fragments
        # Accessible as the property "ec_ndata"
        try:
            value = int(ec_ndata)
            if value <= 0:
                raise ValueError
            self._ec_ndata = value
        except (TypeError, ValueError):
            raise PolicyError('Invalid ec_num_data_fragments %r' %
                              ec_ndata, index=self.idx)

        # Define _ec_nparity as the number of EC parity fragments
        # Accessible as the property "ec_nparity"
        try:
            value = int(ec_nparity)
            if value <= 0:
                raise ValueError
            self._ec_nparity = value
        except (TypeError, ValueError):
            raise PolicyError('Invalid ec_num_parity_fragments %r'
                              % ec_nparity, index=self.idx)

        # Define _ec_segment_size as the encode segment unit size
        # Accessible as the property "ec_segment_size"
        try:
            value = int(ec_segment_size)
            if value <= 0:
                raise ValueError
            self._ec_segment_size = value
        except (TypeError, ValueError):
            raise PolicyError('Invalid ec_object_segment_size %r' %
                              ec_segment_size, index=self.idx)

        # Initialize PyECLib EC backend
        try:
            self.pyeclib_driver = \
                ECDriver(k=self._ec_ndata, m=self._ec_nparity,
                         ec_type=self._ec_type)
        except ECDriverError as e:
            raise PolicyError("Error creating EC policy (%s)" % e,
                              index=self.idx)

        # quorum size in the EC case depends on the choice of EC scheme.
        self._ec_quorum_size = \
            self._ec_ndata + self.pyeclib_driver.min_parity_fragments_needed()

    @property
    def ec_type(self):
        return self._ec_type

    @property
    def ec_ndata(self):
        return self._ec_ndata

    @property
    def ec_nparity(self):
        return self._ec_nparity

    @property
    def ec_segment_size(self):
        return self._ec_segment_size

    @property
    def fragment_size(self):
        """
        Maximum length of a fragment, including header.

        NB: a fragment archive is a sequence of 0 or more max-length
        fragments followed by one possibly-shorter fragment.
        """
        # Technically pyeclib's get_segment_info signature calls for
        # (data_len, segment_size) but on a ranged GET we don't know the
        # ec-content-length header before we need to compute where in the
        # object we should request to align with the fragment size.  So we
        # tell pyeclib a lie - from it's perspective, as long as data_len >=
        # segment_size it'll give us the answer we want.  From our
        # perspective, because we only use this answer to calculate the
        # *minimum* size we should read from an object body even if data_len <
        # segment_size we'll still only read *the whole one and only last
        # fragment* and pass than into pyeclib who will know what to do with
        # it just as it always does when the last fragment is < fragment_size.
        return self.pyeclib_driver.get_segment_info(
            self.ec_segment_size, self.ec_segment_size)['fragment_size']

    @property
    def ec_scheme_description(self):
        """
        This short hand form of the important parts of the ec schema is stored
        in Object System Metadata on the EC Fragment Archives for debugging.
        """
        return "%s %d+%d" % (self._ec_type, self._ec_ndata, self._ec_nparity)

    def __repr__(self):
        return ("%s, EC config(ec_type=%s, ec_segment_size=%d, "
                "ec_ndata=%d, ec_nparity=%d)") % (
                    super(ECStoragePolicy, self).__repr__(), self.ec_type,
                    self.ec_segment_size, self.ec_ndata, self.ec_nparity)

    @classmethod
    def _config_options_map(cls):
        options = super(ECStoragePolicy, cls)._config_options_map()
        options.update({
            'ec_type': 'ec_type',
            'ec_object_segment_size': 'ec_segment_size',
            'ec_num_data_fragments': 'ec_ndata',
            'ec_num_parity_fragments': 'ec_nparity',
        })
        return options

    def get_info(self, config=False):
        info = super(ECStoragePolicy, self).get_info(config=config)
        if not config:
            info.pop('ec_object_segment_size')
            info.pop('ec_num_data_fragments')
            info.pop('ec_num_parity_fragments')
            info.pop('ec_type')
        return info

    def _validate_ring(self):
        """
        EC specific validation

        Replica count check - we need _at_least_ (#data + #parity) replicas
        configured.  Also if the replica count is larger than exactly that
        number there's a non-zero risk of error for code that is considering
        the number of nodes in the primary list from the ring.
        """
        if not self.object_ring:
            raise PolicyError('Ring is not loaded')
        nodes_configured = self.object_ring.replica_count
        if nodes_configured != (self.ec_ndata + self.ec_nparity):
            raise RingValidationError(
                'EC ring for policy %s needs to be configured with '
                'exactly %d nodes. Got %d.' % (self.name,
                self.ec_ndata + self.ec_nparity, nodes_configured))

    @property
    def quorum(self):
        """
        Number of successful backend requests needed for the proxy to consider
        the client request successful.

        The quorum size for EC policies defines the minimum number
        of data + parity elements required to be able to guarantee
        the desired fault tolerance, which is the number of data
        elements supplemented by the minimum number of parity
        elements required by the chosen erasure coding scheme.

        For example, for Reed-Solomon, the minimum number parity
        elements required is 1, and thus the quorum_size requirement
        is ec_ndata + 1.

        Given the number of parity elements required is not the same
        for every erasure coding scheme, consult PyECLib for
        min_parity_fragments_needed()
        """
        return self._ec_quorum_size


class StoragePolicyCollection(object):
    """
    This class represents the collection of valid storage policies for the
    cluster and is instantiated as :class:`StoragePolicy` objects are added to
    the collection when ``swift.conf`` is parsed by
    :func:`parse_storage_policies`.

    When a StoragePolicyCollection is created, the following validation
    is enforced:

    * If a policy with index 0 is not declared and no other policies defined,
      Swift will create one
    * The policy index must be a non-negative integer
    * If no policy is declared as the default and no other policies are
      defined, the policy with index 0 is set as the default
    * Policy indexes must be unique
    * Policy names are required
    * Policy names are case insensitive
    * Policy names must contain only letters, digits or a dash
    * Policy names must be unique
    * The policy name 'Policy-0' can only be used for the policy with index 0
    * If any policies are defined, exactly one policy must be declared default
    * Deprecated policies can not be declared the default

    """
    def __init__(self, pols):
        self.default = []
        self.by_name = {}
        self.by_index = {}
        self._validate_policies(pols)

    def _add_policy(self, policy):
        """
        Add pre-validated policies to internal indexes.
        """
        self.by_name[policy.name.upper()] = policy
        self.by_index[int(policy)] = policy

    def __repr__(self):
        return (textwrap.dedent("""
    StoragePolicyCollection([
        %s
    ])
    """) % ',\n    '.join(repr(p) for p in self)).strip()

    def __len__(self):
        return len(self.by_index)

    def __getitem__(self, key):
        return self.by_index[key]

    def __iter__(self):
        return iter(self.by_index.values())

    def _validate_policies(self, policies):
        """
        :param policies: list of policies
        """

        for policy in policies:
            if int(policy) in self.by_index:
                raise PolicyError('Duplicate index %s conflicts with %s' % (
                    policy, self.get_by_index(int(policy))))
            if policy.name.upper() in self.by_name:
                raise PolicyError('Duplicate name %s conflicts with %s' % (
                    policy, self.get_by_name(policy.name)))
            if policy.is_default:
                if not self.default:
                    self.default = policy
                else:
                    raise PolicyError(
                        'Duplicate default %s conflicts with %s' % (
                            policy, self.default))
            self._add_policy(policy)

        # If a 0 policy wasn't explicitly given, or nothing was
        # provided, create the 0 policy now
        if 0 not in self.by_index:
            if len(self) != 0:
                raise PolicyError('You must specify a storage policy '
                                  'section for policy index 0 in order '
                                  'to define multiple policies')
            self._add_policy(StoragePolicy(0, name=LEGACY_POLICY_NAME))

        # at least one policy must be enabled
        enabled_policies = [p for p in self if not p.is_deprecated]
        if not enabled_policies:
            raise PolicyError("Unable to find policy that's not deprecated!")

        # if needed, specify default
        if not self.default:
            if len(self) > 1:
                raise PolicyError("Unable to find default policy")
            self.default = self[0]
            self.default.is_default = True

    def get_by_name(self, name):
        """
        Find a storage policy by its name.

        :param name: name of the policy
        :returns: storage policy, or None
        """
        return self.by_name.get(name.upper())

    def get_by_index(self, index):
        """
        Find a storage policy by its index.

        An index of None will be treated as 0.

        :param index: numeric index of the storage policy
        :returns: storage policy, or None if no such policy
        """
        # makes it easier for callers to just pass in a header value
        if index in ('', None):
            index = 0
        else:
            try:
                index = int(index)
            except ValueError:
                return None
        return self.by_index.get(index)

    @property
    def legacy(self):
        return self.get_by_index(None)

    def get_object_ring(self, policy_idx, swift_dir):
        """
        Get the ring object to use to handle a request based on its policy.

        An index of None will be treated as 0.

        :param policy_idx: policy index as defined in swift.conf
        :param swift_dir: swift_dir used by the caller
        :returns: appropriate ring object
        """
        policy = self.get_by_index(policy_idx)
        if not policy:
            raise PolicyError("No policy with index %s" % policy_idx)
        if not policy.object_ring:
            policy.load_ring(swift_dir)
        return policy.object_ring

    def get_policy_info(self):
        """
        Build info about policies for the /info endpoint

        :returns: list of dicts containing relevant policy information
        """
        policy_info = []
        for pol in self:
            # delete from /info if deprecated
            if pol.is_deprecated:
                continue
            policy_entry = pol.get_info()
            policy_info.append(policy_entry)
        return policy_info


def parse_storage_policies(conf):
    """
    Parse storage policies in ``swift.conf`` - note that validation
    is done when the :class:`StoragePolicyCollection` is instantiated.

    :param conf: ConfigParser parser object for swift.conf
    """
    policies = []
    for section in conf.sections():
        if not section.startswith('storage-policy:'):
            continue
        policy_index = section.split(':', 1)[1]
        config_options = dict(conf.items(section))
        policy_type = config_options.pop('policy_type', DEFAULT_POLICY_TYPE)
        policy_cls = BaseStoragePolicy.policy_type_to_policy_cls[policy_type]
        policy = policy_cls.from_config(policy_index, config_options)
        policies.append(policy)

    return StoragePolicyCollection(policies)


class StoragePolicySingleton(object):
    """
    An instance of this class is the primary interface to storage policies
    exposed as a module level global named ``POLICIES``.  This global
    reference wraps ``_POLICIES`` which is normally instantiated by parsing
    ``swift.conf`` and will result in an instance of
    :class:`StoragePolicyCollection`.

    You should never patch this instance directly, instead patch the module
    level ``_POLICIES`` instance so that swift code which imported
    ``POLICIES`` directly will reference the patched
    :class:`StoragePolicyCollection`.
    """

    def __iter__(self):
        return iter(_POLICIES)

    def __len__(self):
        return len(_POLICIES)

    def __getitem__(self, key):
        return _POLICIES[key]

    def __getattribute__(self, name):
        return getattr(_POLICIES, name)

    def __repr__(self):
        return repr(_POLICIES)


def reload_storage_policies():
    """
    Reload POLICIES from ``swift.conf``.
    """
    global _POLICIES
    policy_conf = ConfigParser()
    policy_conf.read(SWIFT_CONF_FILE)
    try:
        _POLICIES = parse_storage_policies(policy_conf)
    except PolicyError as e:
        raise SystemExit('ERROR: Invalid Storage Policy Configuration '
                         'in %s (%s)' % (SWIFT_CONF_FILE, e))


# parse configuration and setup singleton
_POLICIES = None
reload_storage_policies()
POLICIES = StoragePolicySingleton()

if __name__  == '__main__':
    reload_storage_policies()
    POLICIES = StoragePolicySingleton()
    PO = StoragePolicyCollection(POLICIES)
    print PO
"""    print "______3_rep_ec___________________"
    POL3 = PO.get_by_index(3)
    print POL3.get_local_policy, POL3.get_cloud_policy
    print "_____4__ec_rep___________________________"
    POL4 = PO.get_by_index(4)
    print POL4.get_local_policy, POL4.get_cloud_policy
    print "_____5___rep__rep____________________"
    POL5 = PO.get_by_index(5)
    print POL5.get_local_policy, POL5.get_cloud_policy
    print "_____6__ec_ec_____________"
    POL6 = PO.get_by_index(6)
    print POL6.get_local_policy, POL6.get_cloud_policy
    print "~~~~~~~~.......~~~~~~~~~~~"
"""


# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Accesses the google.cloud.mail.v1alpha3 CloudMail API."""

import functools
import pkg_resources

import google.api_core.gapic_v1.client_info
import google.api_core.gapic_v1.config
import google.api_core.gapic_v1.method
import google.api_core.grpc_helpers
import google.api_core.page_iterator
import google.api_core.path_template
import google.api_core.protobuf_helpers
import grpc

from google.cloud.mail_v1alpha3.gapic import cloud_mail_client_config
from google.cloud.mail_v1alpha3.gapic import enums
from google.cloud.mail_v1alpha3.proto import address_set_pb2
from google.cloud.mail_v1alpha3.proto import cloud_mail_pb2_grpc
from google.cloud.mail_v1alpha3.proto import domain_pb2
from google.cloud.mail_v1alpha3.proto import email_verified_address_pb2
from google.cloud.mail_v1alpha3.proto import receipt_rule_pb2
from google.cloud.mail_v1alpha3.proto import sender_pb2
from google.cloud.mail_v1alpha3.proto import smtp_credential_pb2
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import policy_pb2
from google.protobuf import empty_pb2
from google.protobuf import field_mask_pb2

_GAPIC_LIBRARY_VERSION = pkg_resources.get_distribution(
    'google-cloud-cloudmail', ).version


class CloudMailClient(object):
    """
    Provides Google Cloud Mail customers a way to manage the service and to send
    mail.  Use this to add or remove domains, define handling for incoming
    messages, and register senders for outbound messages.
    """

    SERVICE_ADDRESS = 'cloudmail.googleapis.com:443'
    """The default address of the service."""

    # The scopes needed to make gRPC calls to all of the methods defined in
    # this service
    _DEFAULT_SCOPES = ('https://www.googleapis.com/auth/cloud-platform', )

    # The name of the interface for this client. This is the key used to find
    # method configuration in the client_config dictionary.
    _INTERFACE_NAME = 'google.cloud.mail.v1alpha3.CloudMail'

    @classmethod
    def project_path(cls, project):
        """Return a fully-qualified project string."""
        return google.api_core.path_template.expand(
            'projects/{project}',
            project=project,
        )

    @classmethod
    def email_verified_address_path(cls, project, region,
                                    email_verified_address):
        """Return a fully-qualified email_verified_address string."""
        return google.api_core.path_template.expand(
            'projects/{project}/regions/{region}/emailVerifiedAddresses/{email_verified_address}',
            project=project,
            region=region,
            email_verified_address=email_verified_address,
        )

    @classmethod
    def sender_path(cls, project, region, sender):
        """Return a fully-qualified sender string."""
        return google.api_core.path_template.expand(
            'projects/{project}/regions/{region}/senders/{sender}',
            project=project,
            region=region,
            sender=sender,
        )

    @classmethod
    def smtp_credential_path(cls, project, region, sender, smtp_credential):
        """Return a fully-qualified smtp_credential string."""
        return google.api_core.path_template.expand(
            'projects/{project}/regions/{region}/senders/{sender}/smtpCredentials/{smtp_credential}',
            project=project,
            region=region,
            sender=sender,
            smtp_credential=smtp_credential,
        )

    @classmethod
    def domain_path(cls, region, domain):
        """Return a fully-qualified domain string."""
        return google.api_core.path_template.expand(
            'regions/{region}/domains/{domain}',
            region=region,
            domain=domain,
        )

    @classmethod
    def address_set_path(cls, region, domain, address_set):
        """Return a fully-qualified address_set string."""
        return google.api_core.path_template.expand(
            'regions/{region}/domains/{domain}/addressSets/{address_set}',
            region=region,
            domain=domain,
            address_set=address_set,
        )

    @classmethod
    def receipt_rule_path(cls, region, domain, receipt_rule):
        """Return a fully-qualified receipt_rule string."""
        return google.api_core.path_template.expand(
            'regions/{region}/domains/{domain}/receiptRules/{receipt_rule}',
            region=region,
            domain=domain,
            receipt_rule=receipt_rule,
        )

    def __init__(self,
                 channel=None,
                 credentials=None,
                 client_config=cloud_mail_client_config.config,
                 client_info=None):
        """Constructor.

        Args:
            channel (grpc.Channel): A ``Channel`` instance through
                which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            client_config (dict): A dictionary of call options for each
                method. If not specified, the default configuration is used.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.
        """
        # If both `channel` and `credentials` are specified, raise an
        # exception (channels come with credentials baked in already).
        if channel is not None and credentials is not None:
            raise ValueError(
                'The `channel` and `credentials` arguments to {} are mutually '
                'exclusive.'.format(self.__class__.__name__), )

        # Create the channel.
        self.channel = channel
        if self.channel is None:
            self.channel = google.api_core.grpc_helpers.create_channel(
                self.SERVICE_ADDRESS,
                credentials=credentials,
                scopes=self._DEFAULT_SCOPES,
            )

        # Create the gRPC stubs.
        self._cloud_mail_stub = (cloud_mail_pb2_grpc.CloudMailStub(
            self.channel))

        if client_info is None:
            client_info = (
                google.api_core.gapic_v1.client_info.DEFAULT_CLIENT_INFO)
        client_info.gapic_version = _GAPIC_LIBRARY_VERSION
        self._client_info = client_info

        # Parse out the default settings for retry and timeout for each RPC
        # from the client configuration.
        # (Ordinarily, these are the defaults specified in the `*_config.py`
        # file next to this one.)
        self._method_configs = google.api_core.gapic_v1.config.parse_method_configs(
            client_config['interfaces'][self._INTERFACE_NAME], )

        self._inner_api_calls = {}

    def _intercept_channel(self, *interceptors):
        """ Experimental. Bind gRPC interceptors to the gRPC channel.

        Args:
            interceptors (*Union[grpc.UnaryUnaryClientInterceptor, grpc.UnaryStreamingClientInterceptor, grpc.StreamingUnaryClientInterceptor, grpc.StreamingStreamingClientInterceptor]):
              Zero or more gRPC interceptors. Interceptors are given control in the order
              they are listed.
        Raises:
            TypeError: If interceptor does not derive from any of
              UnaryUnaryClientInterceptor,
              UnaryStreamClientInterceptor,
              StreamUnaryClientInterceptor, or
              StreamStreamClientInterceptor.
        """
        self.channel = grpc.intercept_channel(self.channel, *interceptors)
        self._cloud_mail_stub = (cloud_mail_pb2_grpc.CloudMailStub(
            self.channel))
        self._inner_api_calls.clear()

    # Service calls
    def list_domains(self,
                     parent,
                     region,
                     show_deleted,
                     retry=google.api_core.gapic_v1.method.DEFAULT,
                     timeout=google.api_core.gapic_v1.method.DEFAULT,
                     metadata=None):
        """
        Lists domains with the given parent.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``parent``:
            >>> parent = ''
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``show_deleted``:
            >>> show_deleted = False
            >>>
            >>> response = client.list_domains(parent, region, show_deleted)

        Args:
            parent (str): Name of the parent resource whose domains are to be retrieved.
                For example, \"projects/prj-123\".
            region (str): Region whose domains are to be listed.
            show_deleted (bool): If true, deleted domains will be included in the returned list. The
                'deleted' field of each domain indicates whether it is deleted.
                If false, deleted domains will be omitted from the returned list.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ListDomainsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_domains' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_domains'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListDomains,
                    default_retry=self._method_configs['ListDomains'].retry,
                    default_timeout=self._method_configs['ListDomains']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.ListDomainsRequest(
            parent=parent,
            region=region,
            show_deleted=show_deleted,
        )
        return self._inner_api_calls['list_domains'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def get_domain(self,
                   name,
                   retry=google.api_core.gapic_v1.method.DEFAULT,
                   timeout=google.api_core.gapic_v1.method.DEFAULT,
                   metadata=None):
        """
        Gets the specified domain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> response = client.get_domain(name)

        Args:
            name (str): Name of the domain to retrieve, like \"regions/us-east1/domains/12345\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetDomain,
                    default_retry=self._method_configs['GetDomain'].retry,
                    default_timeout=self._method_configs['GetDomain'].timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.GetDomainRequest(name=name, )
        return self._inner_api_calls['get_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_domain(self,
                      parent,
                      region,
                      domain,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Registers the specified domain for Cloud Mail.
        Cloudmail can provide a regional, per-project domain name e.g.
        my-project.us-east1.cloudsmtp.net
        where cloudmail manages all of the dns. These can be
        created by calling CreateDomain with Domain.project_domain == true
        and Domain.domain_name == \"\".

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``parent``:
            >>> parent = ''
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``domain``:
            >>> domain = {}
            >>>
            >>> response = client.create_domain(parent, region, domain)

        Args:
            parent (str): The parent resource name where the domain is to be created.
                For example, \"projects/prj-123\".
            region (str): The region in which to create the domain. For example, \"us-east1\".
            domain (Union[dict, ~google.cloud.mail_v1alpha3.types.Domain]): The domain to create.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Domain`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateDomain,
                    default_retry=self._method_configs['CreateDomain'].retry,
                    default_timeout=self._method_configs['CreateDomain']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.CreateDomainRequest(
            parent=parent,
            region=region,
            domain=domain,
        )
        return self._inner_api_calls['create_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_domain(self,
                      domain,
                      update_mask,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Updates the given domain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``domain``:
            >>> domain = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_domain(domain, update_mask)

        Args:
            domain (Union[dict, ~google.cloud.mail_v1alpha3.types.Domain]): The domain to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Domain`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): The fields to update. Required.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateDomain,
                    default_retry=self._method_configs['UpdateDomain'].retry,
                    default_timeout=self._method_configs['UpdateDomain']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.UpdateDomainRequest(
            domain=domain,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_domain(self,
                      name,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Marks a domain as deleted. It will be automatically expunged after 30 days
        unless it is undeleted with UndeleteDomain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> response = client.delete_domain(name)

        Args:
            name (str): Name of the domain to trash, like \"regions/us-east1/domains/12345\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteDomain,
                    default_retry=self._method_configs['DeleteDomain'].retry,
                    default_timeout=self._method_configs['DeleteDomain']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.DeleteDomainRequest(name=name, )
        return self._inner_api_calls['delete_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def undelete_domain(self,
                        name,
                        retry=google.api_core.gapic_v1.method.DEFAULT,
                        timeout=google.api_core.gapic_v1.method.DEFAULT,
                        metadata=None):
        """
        Removes the deleted status for a domain that was previously deleted with
        DeleteDomain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> response = client.undelete_domain(name)

        Args:
            name (str): Name of the domain to undelete, like \"regions/us-east1/domains/12345\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'undelete_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'undelete_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UndeleteDomain,
                    default_retry=self._method_configs['UndeleteDomain'].retry,
                    default_timeout=self._method_configs['UndeleteDomain']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.UndeleteDomainRequest(name=name, )
        return self._inner_api_calls['undelete_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def test_receipt_rules(self,
                           domain,
                           recipient,
                           receipt_ruleset,
                           retry=google.api_core.gapic_v1.method.DEFAULT,
                           timeout=google.api_core.gapic_v1.method.DEFAULT,
                           metadata=None):
        """
        Evaluates a recipient address against the domain's receipt ruleset and
        returns the list of rules that would fire.  Clients may provide an optional
        alternative candidate ruleset to be evaluated instead of the service's
        active ruleset.  This method can be used to verify Cloud Mail behavior for
        incoming messages.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> domain = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``recipient``:
            >>> recipient = ''
            >>>
            >>> # TODO: Initialize ``receipt_ruleset``:
            >>> receipt_ruleset = {}
            >>>
            >>> response = client.test_receipt_rules(domain, recipient, receipt_ruleset)

        Args:
            domain (str): The name of the domain to test, like \"regions/us-east1/domains/12345\".
            recipient (str): Candidate recipient address to evaluate the rule set on.
            receipt_ruleset (Union[dict, ~google.cloud.mail_v1alpha3.types.ReceiptRuleset]): Optional receipt ruleset to evaluate.  If not specified, the recipient is
                evaluated against the domain's receipt ruleset.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.ReceiptRuleset`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.TestReceiptRulesResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'test_receipt_rules' not in self._inner_api_calls:
            self._inner_api_calls[
                'test_receipt_rules'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.TestReceiptRules,
                    default_retry=self._method_configs[
                        'TestReceiptRules'].retry,
                    default_timeout=self._method_configs['TestReceiptRules']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.TestReceiptRulesRequest(
            domain=domain,
            recipient=recipient,
            receipt_ruleset=receipt_ruleset,
        )
        return self._inner_api_calls['test_receipt_rules'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def verify_domain(self,
                      name,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Checks the domain's DNS TXT record for the verification token, and updates
        the status to ACTIVE if valid.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> response = client.verify_domain(name)

        Args:
            name (str): Name of the domain to verify, like \"domains/12345\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Domain` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'verify_domain' not in self._inner_api_calls:
            self._inner_api_calls[
                'verify_domain'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.VerifyDomain,
                    default_retry=self._method_configs['VerifyDomain'].retry,
                    default_timeout=self._method_configs['VerifyDomain']
                    .timeout,
                    client_info=self._client_info,
                )

        request = domain_pb2.VerifyDomainRequest(name=name, )
        return self._inner_api_calls['verify_domain'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def list_email_verified_addresses(
            self,
            parent,
            region,
            show_deleted,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Lists EmailVerifiedAddresses with the given parent.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.project_path('[PROJECT]')
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``show_deleted``:
            >>> show_deleted = False
            >>>
            >>> response = client.list_email_verified_addresses(parent, region, show_deleted)

        Args:
            parent (str): Name of the parent resource whose EmailVerifiedAddresses should be listed,
                such as \"projects/1234\".
            region (str): Name of the cloud region where EmailVerifiedAddresses should be listed,
                for example \"us-east1\".
            show_deleted (bool): Indicates if user wants to list deleted email verified resources. If false,
                deleted email verified addresses will be omitted from the returned list.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ListEmailVerifiedAddressesResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_email_verified_addresses' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_email_verified_addresses'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListEmailVerifiedAddresses,
                    default_retry=self._method_configs[
                        'ListEmailVerifiedAddresses'].retry,
                    default_timeout=self._method_configs[
                        'ListEmailVerifiedAddresses'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.ListEmailVerifiedAddressesRequest(
            parent=parent,
            region=region,
            show_deleted=show_deleted,
        )
        return self._inner_api_calls['list_email_verified_addresses'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def get_email_verified_address(
            self,
            name,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Gets the specified EmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.email_verified_address_path('[PROJECT]', '[REGION]', '[EMAIL_VERIFIED_ADDRESS]')
            >>>
            >>> response = client.get_email_verified_address(name)

        Args:
            name (str): Name of the EmailVerifiedAddress to retrieve, for example
                \"regions/us-east1/emailVerifiedAddresses/abc@example.com-123456\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_email_verified_address' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_email_verified_address'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetEmailVerifiedAddress,
                    default_retry=self._method_configs[
                        'GetEmailVerifiedAddress'].retry,
                    default_timeout=self._method_configs[
                        'GetEmailVerifiedAddress'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.GetEmailVerifiedAddressRequest(
            name=name, )
        return self._inner_api_calls['get_email_verified_address'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_email_verified_address(
            self,
            parent,
            region,
            email_verified_address,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Creates the given EmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.project_path('[PROJECT]')
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``email_verified_address``:
            >>> email_verified_address = {}
            >>>
            >>> response = client.create_email_verified_address(parent, region, email_verified_address)

        Args:
            parent (str): The name of the parent resource, such as \"projects/1234\".
            region (str): The region in which to create the EmailVerifiedAddress, such as \"us-east1\".
            email_verified_address (Union[dict, ~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress]): The EmailVerifiedAddress.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_email_verified_address' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_email_verified_address'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateEmailVerifiedAddress,
                    default_retry=self._method_configs[
                        'CreateEmailVerifiedAddress'].retry,
                    default_timeout=self._method_configs[
                        'CreateEmailVerifiedAddress'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.CreateEmailVerifiedAddressRequest(
            parent=parent,
            region=region,
            email_verified_address=email_verified_address,
        )
        return self._inner_api_calls['create_email_verified_address'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_email_verified_address(
            self,
            email_verified_address,
            update_mask,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Updates the given EmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``email_verified_address``:
            >>> email_verified_address = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_email_verified_address(email_verified_address, update_mask)

        Args:
            email_verified_address (Union[dict, ~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress]): The EmailVerifiedAddress to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): The field to update. Required.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_email_verified_address' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_email_verified_address'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateEmailVerifiedAddress,
                    default_retry=self._method_configs[
                        'UpdateEmailVerifiedAddress'].retry,
                    default_timeout=self._method_configs[
                        'UpdateEmailVerifiedAddress'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.UpdateEmailVerifiedAddressRequest(
            email_verified_address=email_verified_address,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_email_verified_address'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_email_verified_address(
            self,
            name,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Marks the specified EmailVerifiedAddress as deleted. It will be
        automatically expunged after 30 days unless it is undeleted with
        UndeleteEmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.email_verified_address_path('[PROJECT]', '[REGION]', '[EMAIL_VERIFIED_ADDRESS]')
            >>>
            >>> response = client.delete_email_verified_address(name)

        Args:
            name (str): Name of the verified address to delete, like
                \"projects/abc-123/regions/us-east1/emailVerifiedAddresses/abc@foo.com\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_email_verified_address' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_email_verified_address'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteEmailVerifiedAddress,
                    default_retry=self._method_configs[
                        'DeleteEmailVerifiedAddress'].retry,
                    default_timeout=self._method_configs[
                        'DeleteEmailVerifiedAddress'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.DeleteEmailVerifiedAddressRequest(
            name=name, )
        return self._inner_api_calls['delete_email_verified_address'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def undelete_email_verified_address(
            self,
            name,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Undeletes the specified EmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.email_verified_address_path('[PROJECT]', '[REGION]', '[EMAIL_VERIFIED_ADDRESS]')
            >>>
            >>> response = client.undelete_email_verified_address(name)

        Args:
            name (str): Name of the verified address to undelete, like
                \"projects/abc-123/regions/us-east1/emailVerifiedAddresses/abc@foo.com\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'undelete_email_verified_address' not in self._inner_api_calls:
            self._inner_api_calls[
                'undelete_email_verified_address'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UndeleteEmailVerifiedAddress,
                    default_retry=self._method_configs[
                        'UndeleteEmailVerifiedAddress'].retry,
                    default_timeout=self._method_configs[
                        'UndeleteEmailVerifiedAddress'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.UndeleteEmailVerifiedAddressRequest(
            name=name, )
        return self._inner_api_calls['undelete_email_verified_address'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def request_email_verification(
            self,
            name,
            retry=google.api_core.gapic_v1.method.DEFAULT,
            timeout=google.api_core.gapic_v1.method.DEFAULT,
            metadata=None):
        """
        Emails a verification token to an unverified EmailVerifiedAddress.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.email_verified_address_path('[PROJECT]', '[REGION]', '[EMAIL_VERIFIED_ADDRESS]')
            >>>
            >>> response = client.request_email_verification(name)

        Args:
            name (str): Name of the address to verify, like
                \"projects/abc-123/regions/us-east1/emailVerifiedAddresses/abc@foo.com\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.RequestEmailVerificationResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'request_email_verification' not in self._inner_api_calls:
            self._inner_api_calls[
                'request_email_verification'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.RequestEmailVerification,
                    default_retry=self._method_configs[
                        'RequestEmailVerification'].retry,
                    default_timeout=self._method_configs[
                        'RequestEmailVerification'].timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.RequestEmailVerificationRequest(
            name=name, )
        return self._inner_api_calls['request_email_verification'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def verify_email(self,
                     name,
                     token,
                     retry=google.api_core.gapic_v1.method.DEFAULT,
                     timeout=google.api_core.gapic_v1.method.DEFAULT,
                     metadata=None):
        """
        Checks token and verifies EmailVerifiedAddress

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.email_verified_address_path('[PROJECT]', '[REGION]', '[EMAIL_VERIFIED_ADDRESS]')
            >>>
            >>> # TODO: Initialize ``token``:
            >>> token = ''
            >>>
            >>> response = client.verify_email(name, token)

        Args:
            name (str): Name of the address to verify, like
                \"projects/abc-123/regions/us-east1/emailVerifiedAddresses/abc@foo.com\".
            token (str): Token to be used for validation.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.EmailVerifiedAddress` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'verify_email' not in self._inner_api_calls:
            self._inner_api_calls[
                'verify_email'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.VerifyEmail,
                    default_retry=self._method_configs['VerifyEmail'].retry,
                    default_timeout=self._method_configs['VerifyEmail']
                    .timeout,
                    client_info=self._client_info,
                )

        request = email_verified_address_pb2.VerifyEmailRequest(
            name=name,
            token=token,
        )
        return self._inner_api_calls['verify_email'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def list_senders(self,
                     parent,
                     region,
                     show_deleted,
                     retry=google.api_core.gapic_v1.method.DEFAULT,
                     timeout=google.api_core.gapic_v1.method.DEFAULT,
                     metadata=None):
        """
        Lists senders for the given parent.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.project_path('[PROJECT]')
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``show_deleted``:
            >>> show_deleted = False
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_senders(parent, region, show_deleted):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_senders(parent, region, show_deleted, options=CallOptions(page_token=INITIAL_PAGE)):
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Name of the parent whose senders are to be retrieved, like
                \"projects/1234\".
            region (str): The region whose Senders should be listed. For example, \"us-east1\".
            show_deleted (bool): Indicates if user wants to list deleted senders. If false, deleted senders
                will be omitted from the returned list.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.gax.PageIterator` instance. By default, this
            is an iterable of :class:`~google.cloud.mail_v1alpha3.types.Sender` instances.
            This object can also be configured to iterate over the pages
            of the response through the `options` parameter.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_senders' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_senders'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListSenders,
                    default_retry=self._method_configs['ListSenders'].retry,
                    default_timeout=self._method_configs['ListSenders']
                    .timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.ListSendersRequest(
            parent=parent,
            region=region,
            show_deleted=show_deleted,
        )
        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls['list_senders'],
                retry=retry,
                timeout=timeout,
                metadata=metadata),
            request=request,
            items_field='senders',
            request_token_field='page_token',
            response_token_field='next_page_token',
        )
        return iterator

    def get_sender(self,
                   name,
                   retry=google.api_core.gapic_v1.method.DEFAULT,
                   timeout=google.api_core.gapic_v1.method.DEFAULT,
                   metadata=None):
        """
        Gets the specified sender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> response = client.get_sender(name)

        Args:
            name (str): Name of the sender to retrieve, like
                \"projects/1234/regions/us-east1/senders/abc\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Sender` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_sender' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_sender'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetSender,
                    default_retry=self._method_configs['GetSender'].retry,
                    default_timeout=self._method_configs['GetSender'].timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.GetSenderRequest(name=name, )
        return self._inner_api_calls['get_sender'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_sender(self,
                      parent,
                      region,
                      sender_id,
                      sender,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Creates the specified sender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.project_path('[PROJECT]')
            >>>
            >>> # TODO: Initialize ``region``:
            >>> region = ''
            >>>
            >>> # TODO: Initialize ``sender_id``:
            >>> sender_id = ''
            >>>
            >>> # TODO: Initialize ``sender``:
            >>> sender = {}
            >>>
            >>> response = client.create_sender(parent, region, sender_id, sender)

        Args:
            parent (str): The resource name of the parent; for example, \"projects/abc-123\".
            region (str): The region in which to create the Sender. For example, \"us-east1\".
            sender_id (str): The client-assigned name for the sender. The ID must be an ASCII string
                consisting only of uppercase and lowercase letters, digits, and hyphens.
                The maximum length is 128 bytes.
            sender (Union[dict, ~google.cloud.mail_v1alpha3.types.Sender]): The sender to create.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Sender`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Sender` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_sender' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_sender'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateSender,
                    default_retry=self._method_configs['CreateSender'].retry,
                    default_timeout=self._method_configs['CreateSender']
                    .timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.CreateSenderRequest(
            parent=parent,
            region=region,
            sender_id=sender_id,
            sender=sender,
        )
        return self._inner_api_calls['create_sender'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_sender(self,
                      sender,
                      update_mask,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Updates the specified sender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``sender``:
            >>> sender = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_sender(sender, update_mask)

        Args:
            sender (Union[dict, ~google.cloud.mail_v1alpha3.types.Sender]): The sender to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Sender`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): The fields to update. Required.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Sender` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_sender' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_sender'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateSender,
                    default_retry=self._method_configs['UpdateSender'].retry,
                    default_timeout=self._method_configs['UpdateSender']
                    .timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.UpdateSenderRequest(
            sender=sender,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_sender'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_sender(self,
                      name,
                      retry=google.api_core.gapic_v1.method.DEFAULT,
                      timeout=google.api_core.gapic_v1.method.DEFAULT,
                      metadata=None):
        """
        Marks the specified sender as deleted. It will be automatically expunged
        after 30 days unless it is undeleted with UndeleteSender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> response = client.delete_sender(name)

        Args:
            name (str): Name of the sender to delete, like
                \"projects/1234/regions/us-east1/senders/abc\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Sender` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_sender' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_sender'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteSender,
                    default_retry=self._method_configs['DeleteSender'].retry,
                    default_timeout=self._method_configs['DeleteSender']
                    .timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.DeleteSenderRequest(name=name, )
        return self._inner_api_calls['delete_sender'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def undelete_sender(self,
                        name,
                        retry=google.api_core.gapic_v1.method.DEFAULT,
                        timeout=google.api_core.gapic_v1.method.DEFAULT,
                        metadata=None):
        """
        Undeletes the specified sender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> response = client.undelete_sender(name)

        Args:
            name (str): Name of the sender to undelete, like
                \"projects/1234/regions/us-east1/senders/abc\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Sender` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'undelete_sender' not in self._inner_api_calls:
            self._inner_api_calls[
                'undelete_sender'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UndeleteSender,
                    default_retry=self._method_configs['UndeleteSender'].retry,
                    default_timeout=self._method_configs['UndeleteSender']
                    .timeout,
                    client_info=self._client_info,
                )

        request = sender_pb2.UndeleteSenderRequest(name=name, )
        return self._inner_api_calls['undelete_sender'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def send_message(self,
                     sender,
                     envelope_from_authority,
                     header_from_authority,
                     envelope_from_address,
                     simple_message=None,
                     rfc822_message=None,
                     retry=google.api_core.gapic_v1.method.DEFAULT,
                     timeout=google.api_core.gapic_v1.method.DEFAULT,
                     metadata=None):
        """
        Sends a message using the specified sender.  The \"From\" address in the
        message headers must be a registered and verified domain with the service,
        and it must also match the sender's list of allowed \"From\" patterns;
        otherwise, the request will fail with a FAILED_PRECONDITION error.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> sender = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> # TODO: Initialize ``envelope_from_authority``:
            >>> envelope_from_authority = ''
            >>>
            >>> # TODO: Initialize ``header_from_authority``:
            >>> header_from_authority = ''
            >>>
            >>> # TODO: Initialize ``envelope_from_address``:
            >>> envelope_from_address = ''
            >>>
            >>> response = client.send_message(sender, envelope_from_authority, header_from_authority, envelope_from_address)

        Args:
            sender (str): Name of the sender used to send this message, like
                \"projects/1234/regions/us-east1/senders/abc\".
            envelope_from_authority (str): The URL of an AddressSet that authorizes the envelope_from_address.
                If omitted, the sender's default_envelope_from_authority will be used.
            header_from_authority (str): The URL of an EmailVerifiedAddress or AddressSet that authorizes
                the RFC 822 header from address. If omitted, the sender's
                default_header_from_authority will be used.
            envelope_from_address (str): SMTP envelope from which to send the message. This must match the
                AddressSet indicated by the envelope_from_authority (if provided) or the
                Sender's default_envelope_from_authority.
            simple_message (Union[dict, ~google.cloud.mail_v1alpha3.types.SimpleMessage]): Message format that defines basic headers and content.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.SimpleMessage`
            rfc822_message (Union[dict, ~google.cloud.mail_v1alpha3.types.Rfc822Message]): Message in RFC 822 format.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Rfc822Message`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.SendMessageResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'send_message' not in self._inner_api_calls:
            self._inner_api_calls[
                'send_message'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.SendMessage,
                    default_retry=self._method_configs['SendMessage'].retry,
                    default_timeout=self._method_configs['SendMessage']
                    .timeout,
                    client_info=self._client_info,
                )

        # Sanity check: We have some fields which are mutually exclusive;
        # raise ValueError if more than one is sent.
        google.api_core.protobuf_helpers.check_oneof(
            simple_message=simple_message,
            rfc822_message=rfc822_message,
        )

        request = sender_pb2.SendMessageRequest(
            sender=sender,
            envelope_from_authority=envelope_from_authority,
            header_from_authority=header_from_authority,
            envelope_from_address=envelope_from_address,
            simple_message=simple_message,
            rfc822_message=rfc822_message,
        )
        return self._inner_api_calls['send_message'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def list_smtp_credentials(self,
                              parent,
                              retry=google.api_core.gapic_v1.method.DEFAULT,
                              timeout=google.api_core.gapic_v1.method.DEFAULT,
                              metadata=None):
        """
        Lists SMTP credentials for the specified sender.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> response = client.list_smtp_credentials(parent)

        Args:
            parent (str): Name of the sender whose SMTP credentials are to be retrieved, like
                \"projects/1234/regions/us-east1/senders/abc\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ListSmtpCredentialsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_smtp_credentials' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_smtp_credentials'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListSmtpCredentials,
                    default_retry=self._method_configs[
                        'ListSmtpCredentials'].retry,
                    default_timeout=self._method_configs['ListSmtpCredentials']
                    .timeout,
                    client_info=self._client_info,
                )

        request = smtp_credential_pb2.ListSmtpCredentialsRequest(
            parent=parent, )
        return self._inner_api_calls['list_smtp_credentials'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def get_smtp_credential(self,
                            name,
                            retry=google.api_core.gapic_v1.method.DEFAULT,
                            timeout=google.api_core.gapic_v1.method.DEFAULT,
                            metadata=None):
        """
        Gets the specified SMTP credential.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]', '[SMTP_CREDENTIAL]')
            >>>
            >>> response = client.get_smtp_credential(name)

        Args:
            name (str): Name of the SMTP credential to retrieve, like
                \"projects/1234/regions/us-east1/senders/abc/smtpCredentials/xyz\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.SmtpCredential` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_smtp_credential' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_smtp_credential'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetSmtpCredential,
                    default_retry=self._method_configs[
                        'GetSmtpCredential'].retry,
                    default_timeout=self._method_configs['GetSmtpCredential']
                    .timeout,
                    client_info=self._client_info,
                )

        request = smtp_credential_pb2.GetSmtpCredentialRequest(name=name, )
        return self._inner_api_calls['get_smtp_credential'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_smtp_credential(self,
                               parent,
                               smtp_credential_id,
                               smtp_credential,
                               retry=google.api_core.gapic_v1.method.DEFAULT,
                               timeout=google.api_core.gapic_v1.method.DEFAULT,
                               metadata=None):
        """
        Creates the specified SMTP credential.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
            >>>
            >>> # TODO: Initialize ``smtp_credential_id``:
            >>> smtp_credential_id = ''
            >>>
            >>> # TODO: Initialize ``smtp_credential``:
            >>> smtp_credential = {}
            >>>
            >>> response = client.create_smtp_credential(parent, smtp_credential_id, smtp_credential)

        Args:
            parent (str): Name of the sender to register the SMTP credential under, like
                \"projects/1234/regions/us-east1/senders/abc\".
            smtp_credential_id (str): The client-assigned name for the credential. The ID must be an ASCII string
                consisting only of uppercase and lowercase letters, digits, and hyphens.
                The maximum length is 128 bytes.
            smtp_credential (Union[dict, ~google.cloud.mail_v1alpha3.types.SmtpCredential]): The SMTP credential to create.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.SmtpCredential`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.SmtpCredential` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_smtp_credential' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_smtp_credential'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateSmtpCredential,
                    default_retry=self._method_configs['CreateSmtpCredential']
                    .retry,
                    default_timeout=self._method_configs[
                        'CreateSmtpCredential'].timeout,
                    client_info=self._client_info,
                )

        request = smtp_credential_pb2.CreateSmtpCredentialRequest(
            parent=parent,
            smtp_credential_id=smtp_credential_id,
            smtp_credential=smtp_credential,
        )
        return self._inner_api_calls['create_smtp_credential'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_smtp_credential(self,
                               smtp_credential,
                               update_mask,
                               retry=google.api_core.gapic_v1.method.DEFAULT,
                               timeout=google.api_core.gapic_v1.method.DEFAULT,
                               metadata=None):
        """
        Updates the specified SMTP credential.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``smtp_credential``:
            >>> smtp_credential = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_smtp_credential(smtp_credential, update_mask)

        Args:
            smtp_credential (Union[dict, ~google.cloud.mail_v1alpha3.types.SmtpCredential]): The SMTP credential to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.SmtpCredential`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): The fields to update. Required.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.SmtpCredential` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_smtp_credential' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_smtp_credential'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateSmtpCredential,
                    default_retry=self._method_configs['UpdateSmtpCredential']
                    .retry,
                    default_timeout=self._method_configs[
                        'UpdateSmtpCredential'].timeout,
                    client_info=self._client_info,
                )

        request = smtp_credential_pb2.UpdateSmtpCredentialRequest(
            smtp_credential=smtp_credential,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_smtp_credential'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_smtp_credential(self,
                               name,
                               retry=google.api_core.gapic_v1.method.DEFAULT,
                               timeout=google.api_core.gapic_v1.method.DEFAULT,
                               metadata=None):
        """
        Deletes the specified SMTP credential.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]', '[SMTP_CREDENTIAL]')
            >>>
            >>> client.delete_smtp_credential(name)

        Args:
            name (str): Name of the SMTP credential to delete, like
                \"projects/1234/regions/us-east1/senders/abc/smtpCredentials/xyz\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_smtp_credential' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_smtp_credential'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteSmtpCredential,
                    default_retry=self._method_configs['DeleteSmtpCredential']
                    .retry,
                    default_timeout=self._method_configs[
                        'DeleteSmtpCredential'].timeout,
                    client_info=self._client_info,
                )

        request = smtp_credential_pb2.DeleteSmtpCredentialRequest(name=name, )
        self._inner_api_calls['delete_smtp_credential'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def list_receipt_rules(self,
                           parent,
                           retry=google.api_core.gapic_v1.method.DEFAULT,
                           timeout=google.api_core.gapic_v1.method.DEFAULT,
                           metadata=None):
        """
        Lists receipt rules for the specified Cloud Mail domain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_receipt_rules(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_receipt_rules(parent, options=CallOptions(page_token=INITIAL_PAGE)):
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Name of the domain whose receipt rules are to be retrieved, like
                \"regions/us-east1/domains/1234\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.gax.PageIterator` instance. By default, this
            is an iterable of :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule` instances.
            This object can also be configured to iterate over the pages
            of the response through the `options` parameter.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_receipt_rules' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_receipt_rules'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListReceiptRules,
                    default_retry=self._method_configs[
                        'ListReceiptRules'].retry,
                    default_timeout=self._method_configs['ListReceiptRules']
                    .timeout,
                    client_info=self._client_info,
                )

        request = receipt_rule_pb2.ListReceiptRulesRequest(parent=parent, )
        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls['list_receipt_rules'],
                retry=retry,
                timeout=timeout,
                metadata=metadata),
            request=request,
            items_field='receipt_rules',
            request_token_field='page_token',
            response_token_field='next_page_token',
        )
        return iterator

    def get_receipt_rule(self,
                         name,
                         retry=google.api_core.gapic_v1.method.DEFAULT,
                         timeout=google.api_core.gapic_v1.method.DEFAULT,
                         metadata=None):
        """
        Gets the specified receipt rule.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.receipt_rule_path('[REGION]', '[DOMAIN]', '[RECEIPT_RULE]')
            >>>
            >>> response = client.get_receipt_rule(name)

        Args:
            name (str): Name of the receipt rule to retrieve, like
                \"regions/us-east1/domains/1234/receiptRules/5678\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_receipt_rule' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_receipt_rule'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetReceiptRule,
                    default_retry=self._method_configs['GetReceiptRule'].retry,
                    default_timeout=self._method_configs['GetReceiptRule']
                    .timeout,
                    client_info=self._client_info,
                )

        request = receipt_rule_pb2.GetReceiptRuleRequest(name=name, )
        return self._inner_api_calls['get_receipt_rule'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_receipt_rule(self,
                            parent,
                            rule_id,
                            receipt_rule,
                            retry=google.api_core.gapic_v1.method.DEFAULT,
                            timeout=google.api_core.gapic_v1.method.DEFAULT,
                            metadata=None):
        """
        Creates the specified receipt rule.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``rule_id``:
            >>> rule_id = ''
            >>>
            >>> # TODO: Initialize ``receipt_rule``:
            >>> receipt_rule = {}
            >>>
            >>> response = client.create_receipt_rule(parent, rule_id, receipt_rule)

        Args:
            parent (str): Name of the domain to create the receipt rule for, like
                \"regions/us-east1/domains/1234\".
            rule_id (str): Optional client-assigned name for the receipt rule. If not specified, a
                random name will be assigned by the server.
                If specified, the ID must be an ASCII string consisting only of uppercase
                and lowercase letters, digits, and hyphens. The maximum length is 128
                bytes.
            receipt_rule (Union[dict, ~google.cloud.mail_v1alpha3.types.ReceiptRule]): The receipt rule to create. The 'name' field is ignored, since the name
                will be determined by the parent and rule name.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_receipt_rule' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_receipt_rule'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateReceiptRule,
                    default_retry=self._method_configs[
                        'CreateReceiptRule'].retry,
                    default_timeout=self._method_configs['CreateReceiptRule']
                    .timeout,
                    client_info=self._client_info,
                )

        request = receipt_rule_pb2.CreateReceiptRuleRequest(
            parent=parent,
            rule_id=rule_id,
            receipt_rule=receipt_rule,
        )
        return self._inner_api_calls['create_receipt_rule'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_receipt_rule(self,
                            receipt_rule,
                            update_mask,
                            retry=google.api_core.gapic_v1.method.DEFAULT,
                            timeout=google.api_core.gapic_v1.method.DEFAULT,
                            metadata=None):
        """
        Updates the specified receipt rule.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``receipt_rule``:
            >>> receipt_rule = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_receipt_rule(receipt_rule, update_mask)

        Args:
            receipt_rule (Union[dict, ~google.cloud.mail_v1alpha3.types.ReceiptRule]): The receipt rule to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): The fields to update. Required.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ReceiptRule` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_receipt_rule' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_receipt_rule'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateReceiptRule,
                    default_retry=self._method_configs[
                        'UpdateReceiptRule'].retry,
                    default_timeout=self._method_configs['UpdateReceiptRule']
                    .timeout,
                    client_info=self._client_info,
                )

        request = receipt_rule_pb2.UpdateReceiptRuleRequest(
            receipt_rule=receipt_rule,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_receipt_rule'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_receipt_rule(self,
                            name,
                            retry=google.api_core.gapic_v1.method.DEFAULT,
                            timeout=google.api_core.gapic_v1.method.DEFAULT,
                            metadata=None):
        """
        Deletes the specified receipt rule.  If the rule is part of the domain's
        active ruleset, the rule reference is also removed from the ruleset.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.receipt_rule_path('[REGION]', '[DOMAIN]', '[RECEIPT_RULE]')
            >>>
            >>> client.delete_receipt_rule(name)

        Args:
            name (str): Name of the receipt rule to delete, like
                \"regions/us-east1/domains/1234/receiptRules/5678\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_receipt_rule' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_receipt_rule'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteReceiptRule,
                    default_retry=self._method_configs[
                        'DeleteReceiptRule'].retry,
                    default_timeout=self._method_configs['DeleteReceiptRule']
                    .timeout,
                    client_info=self._client_info,
                )

        request = receipt_rule_pb2.DeleteReceiptRuleRequest(name=name, )
        self._inner_api_calls['delete_receipt_rule'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def list_address_sets(self,
                          parent,
                          show_deleted,
                          retry=google.api_core.gapic_v1.method.DEFAULT,
                          timeout=google.api_core.gapic_v1.method.DEFAULT,
                          metadata=None):
        """
        Lists AddressSets for the specified Cloud Mail domain.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``show_deleted``:
            >>> show_deleted = False
            >>>
            >>> response = client.list_address_sets(parent, show_deleted)

        Args:
            parent (str): Name of the domain whose AddressSets are to be retrieved, like
                \"regions/us-east1/domains/1234\".
            show_deleted (bool): Indicates if user wants to list deleted AddressSets
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.ListAddressSetsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'list_address_sets' not in self._inner_api_calls:
            self._inner_api_calls[
                'list_address_sets'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.ListAddressSets,
                    default_retry=self._method_configs[
                        'ListAddressSets'].retry,
                    default_timeout=self._method_configs['ListAddressSets']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.ListAddressSetsRequest(
            parent=parent,
            show_deleted=show_deleted,
        )
        return self._inner_api_calls['list_address_sets'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def get_address_set(self,
                        name,
                        retry=google.api_core.gapic_v1.method.DEFAULT,
                        timeout=google.api_core.gapic_v1.method.DEFAULT,
                        metadata=None):
        """
        Gets the specified AddressSet.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')
            >>>
            >>> response = client.get_address_set(name)

        Args:
            name (str): Name of the AddressSet to retrieve, like
                \"regions/us-east1/domains/1234/addressSets/xyz\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.AddressSet` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_address_set' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_address_set'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetAddressSet,
                    default_retry=self._method_configs['GetAddressSet'].retry,
                    default_timeout=self._method_configs['GetAddressSet']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.GetAddressSetRequest(name=name, )
        return self._inner_api_calls['get_address_set'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def create_address_set(self,
                           parent,
                           address_set_id,
                           address_set,
                           retry=google.api_core.gapic_v1.method.DEFAULT,
                           timeout=google.api_core.gapic_v1.method.DEFAULT,
                           metadata=None):
        """
        Creates the specified AddressSet.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> parent = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``address_set_id``:
            >>> address_set_id = ''
            >>>
            >>> # TODO: Initialize ``address_set``:
            >>> address_set = {}
            >>>
            >>> response = client.create_address_set(parent, address_set_id, address_set)

        Args:
            parent (str): Name of the domain to create the receipt rule for, like
                \"regions/us-east1/domains/1234\".
            address_set_id (str): Optional client-assigned name for the address set. If not specified, a
                random name will be assigned by the server.
                If specified, the ID must be an ASCII string consisting only of uppercase
                and lowercase letters, digits, and hyphens. The maximum length is 128
                bytes.
            address_set (Union[dict, ~google.cloud.mail_v1alpha3.types.AddressSet]): The AddressSet to create.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.AddressSet`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.AddressSet` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'create_address_set' not in self._inner_api_calls:
            self._inner_api_calls[
                'create_address_set'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.CreateAddressSet,
                    default_retry=self._method_configs[
                        'CreateAddressSet'].retry,
                    default_timeout=self._method_configs['CreateAddressSet']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.CreateAddressSetRequest(
            parent=parent,
            address_set_id=address_set_id,
            address_set=address_set,
        )
        return self._inner_api_calls['create_address_set'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def update_address_set(self,
                           address_set,
                           update_mask,
                           retry=google.api_core.gapic_v1.method.DEFAULT,
                           timeout=google.api_core.gapic_v1.method.DEFAULT,
                           metadata=None):
        """
        Updates the specified AddressSet.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> # TODO: Initialize ``address_set``:
            >>> address_set = {}
            >>>
            >>> # TODO: Initialize ``update_mask``:
            >>> update_mask = {}
            >>>
            >>> response = client.update_address_set(address_set, update_mask)

        Args:
            address_set (Union[dict, ~google.cloud.mail_v1alpha3.types.AddressSet]): The AddressSet that replaces the resource on the server.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.AddressSet`
            update_mask (Union[dict, ~google.cloud.mail_v1alpha3.types.FieldMask]): Which fields of the address_set to update.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.AddressSet` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'update_address_set' not in self._inner_api_calls:
            self._inner_api_calls[
                'update_address_set'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UpdateAddressSet,
                    default_retry=self._method_configs[
                        'UpdateAddressSet'].retry,
                    default_timeout=self._method_configs['UpdateAddressSet']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.UpdateAddressSetRequest(
            address_set=address_set,
            update_mask=update_mask,
        )
        return self._inner_api_calls['update_address_set'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def delete_address_set(self,
                           name,
                           retry=google.api_core.gapic_v1.method.DEFAULT,
                           timeout=google.api_core.gapic_v1.method.DEFAULT,
                           metadata=None):
        """
        Marks the specified AddressSet as deleted. It will be automatically
        expunged after 30 days unless it is undeleted with UndeleteAddressSet.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')
            >>>
            >>> response = client.delete_address_set(name)

        Args:
            name (str): Name of the AddressSet to delete, like
                \"regions/us-east1/domains/1234/addressSets/xyz\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.AddressSet` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'delete_address_set' not in self._inner_api_calls:
            self._inner_api_calls[
                'delete_address_set'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.DeleteAddressSet,
                    default_retry=self._method_configs[
                        'DeleteAddressSet'].retry,
                    default_timeout=self._method_configs['DeleteAddressSet']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.DeleteAddressSetRequest(name=name, )
        return self._inner_api_calls['delete_address_set'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def undelete_address_set(self,
                             name,
                             retry=google.api_core.gapic_v1.method.DEFAULT,
                             timeout=google.api_core.gapic_v1.method.DEFAULT,
                             metadata=None):
        """
        Undeletes the specified AddressSet.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')
            >>>
            >>> response = client.undelete_address_set(name)

        Args:
            name (str): Name of the AddressSet to undelete, like
                \"regions/us-east1/domains/1234/addressSets/xyz\".
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.AddressSet` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'undelete_address_set' not in self._inner_api_calls:
            self._inner_api_calls[
                'undelete_address_set'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.UndeleteAddressSet,
                    default_retry=self._method_configs[
                        'UndeleteAddressSet'].retry,
                    default_timeout=self._method_configs['UndeleteAddressSet']
                    .timeout,
                    client_info=self._client_info,
                )

        request = address_set_pb2.UndeleteAddressSetRequest(name=name, )
        return self._inner_api_calls['undelete_address_set'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def get_iam_policy(self,
                       resource,
                       retry=google.api_core.gapic_v1.method.DEFAULT,
                       timeout=google.api_core.gapic_v1.method.DEFAULT,
                       metadata=None):
        """
        Gets the access control policy for Cloud Mail resources.
        Returns an empty policy if the resource exists and does not have a policy
        set.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> resource = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> response = client.get_iam_policy(resource)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being requested.
                ``resource`` is usually specified as a path. For example, a Project
                resource is specified as ``projects/{project}``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'get_iam_policy' not in self._inner_api_calls:
            self._inner_api_calls[
                'get_iam_policy'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.GetIamPolicy,
                    default_retry=self._method_configs['GetIamPolicy'].retry,
                    default_timeout=self._method_configs['GetIamPolicy']
                    .timeout,
                    client_info=self._client_info,
                )

        request = iam_policy_pb2.GetIamPolicyRequest(resource=resource, )
        return self._inner_api_calls['get_iam_policy'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def set_iam_policy(self,
                       resource,
                       policy,
                       retry=google.api_core.gapic_v1.method.DEFAULT,
                       timeout=google.api_core.gapic_v1.method.DEFAULT,
                       metadata=None):
        """
        Sets the access control policy for a Cloud Mail Resources. Replaces
        any existing policy.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> resource = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``policy``:
            >>> policy = {}
            >>>
            >>> response = client.set_iam_policy(resource, policy)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being specified.
                ``resource`` is usually specified as a path. For example, a Project
                resource is specified as ``projects/{project}``.
            policy (Union[dict, ~google.cloud.mail_v1alpha3.types.Policy]): REQUIRED: The complete policy to be applied to the ``resource``. The size of
                the policy is limited to a few 10s of KB. An empty policy is a
                valid policy but certain Cloud Platform services (such as Projects)
                might reject them.
                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.mail_v1alpha3.types.Policy`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'set_iam_policy' not in self._inner_api_calls:
            self._inner_api_calls[
                'set_iam_policy'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.SetIamPolicy,
                    default_retry=self._method_configs['SetIamPolicy'].retry,
                    default_timeout=self._method_configs['SetIamPolicy']
                    .timeout,
                    client_info=self._client_info,
                )

        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=resource,
            policy=policy,
        )
        return self._inner_api_calls['set_iam_policy'](
            request, retry=retry, timeout=timeout, metadata=metadata)

    def test_iam_permissions(self,
                             resource,
                             permissions,
                             retry=google.api_core.gapic_v1.method.DEFAULT,
                             timeout=google.api_core.gapic_v1.method.DEFAULT,
                             metadata=None):
        """
        Returns permissions that a caller has on a Cloud Mail Resource.
        If the resource does not exist, this will return an empty set of
        permissions, not a ``NOT_FOUND`` error.

        Note: This operation is designed to be used for building permission-aware
        UIs and command-line tools, not for authorization checking. This operation
        may \"fail open\" without warning.

        Example:
            >>> from google.cloud import mail_v1alpha3
            >>>
            >>> client = mail_v1alpha3.CloudMailClient()
            >>>
            >>> resource = client.domain_path('[REGION]', '[DOMAIN]')
            >>>
            >>> # TODO: Initialize ``permissions``:
            >>> permissions = []
            >>>
            >>> response = client.test_iam_permissions(resource, permissions)

        Args:
            resource (str): REQUIRED: The resource for which the policy detail is being requested.
                ``resource`` is usually specified as a path. For example, a Project
                resource is specified as ``projects/{project}``.
            permissions (list[str]): The set of permissions to check for the ``resource``. Permissions with
                wildcards (such as '*' or 'storage.*') are not allowed. For more
                information see
                `IAM Overview <https://cloud.google.com/iam/docs/overview#permissions>`_.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will not
                be retried.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.mail_v1alpha3.types.TestIamPermissionsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        if 'test_iam_permissions' not in self._inner_api_calls:
            self._inner_api_calls[
                'test_iam_permissions'] = google.api_core.gapic_v1.method.wrap_method(
                    self._cloud_mail_stub.TestIamPermissions,
                    default_retry=self._method_configs[
                        'TestIamPermissions'].retry,
                    default_timeout=self._method_configs['TestIamPermissions']
                    .timeout,
                    client_info=self._client_info,
                )

        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=resource,
            permissions=permissions,
        )
        return self._inner_api_calls['test_iam_permissions'](
            request, retry=retry, timeout=timeout, metadata=metadata)

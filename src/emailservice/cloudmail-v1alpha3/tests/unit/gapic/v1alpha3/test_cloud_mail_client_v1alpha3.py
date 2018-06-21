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
"""Unit tests."""

import pytest

from google.cloud import mail_v1alpha3
from google.cloud.mail_v1alpha3.proto import address_set_pb2
from google.cloud.mail_v1alpha3.proto import domain_pb2
from google.cloud.mail_v1alpha3.proto import email_verified_address_pb2
from google.cloud.mail_v1alpha3.proto import receipt_rule_pb2
from google.cloud.mail_v1alpha3.proto import sender_pb2
from google.cloud.mail_v1alpha3.proto import smtp_credential_pb2
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import policy_pb2
from google.protobuf import empty_pb2
from google.protobuf import field_mask_pb2


class MultiCallableStub(object):
    """Stub for the grpc.UnaryUnaryMultiCallable interface."""

    def __init__(self, method, channel_stub):
        self.method = method
        self.channel_stub = channel_stub

    def __call__(self, request, timeout=None, metadata=None, credentials=None):
        self.channel_stub.requests.append((self.method, request))

        response = None
        if self.channel_stub.responses:
            response = self.channel_stub.responses.pop()

        if isinstance(response, Exception):
            raise response

        if response:
            return response


class ChannelStub(object):
    """Stub for the grpc.Channel interface."""

    def __init__(self, responses=[]):
        self.responses = responses
        self.requests = []

    def unary_unary(self,
                    method,
                    request_serializer=None,
                    response_deserializer=None):
        return MultiCallableStub(method, self)


class CustomException(Exception):
    pass


class TestCloudMailClient(object):
    def test_list_domains(self):
        # Setup Expected Response
        expected_response = {}
        expected_response = domain_pb2.ListDomainsResponse(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = 'parent-995424086'
        region = 'region-934795532'
        show_deleted = False

        response = client.list_domains(parent, region, show_deleted)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.ListDomainsRequest(
            parent=parent, region=region, show_deleted=show_deleted)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_domains_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = 'parent-995424086'
        region = 'region-934795532'
        show_deleted = False

        with pytest.raises(CustomException):
            client.list_domains(parent, region, show_deleted)

    def test_get_domain(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name_2,
            'parent': parent,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        response = client.get_domain(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.GetDomainRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        with pytest.raises(CustomException):
            client.get_domain(name)

    def test_create_domain(self):
        # Setup Expected Response
        name = 'name3373707'
        parent_2 = 'parent21175163357'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name,
            'parent': parent_2,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = 'parent-995424086'
        region = 'region-934795532'
        domain = {}

        response = client.create_domain(parent, region, domain)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.CreateDomainRequest(
            parent=parent, region=region, domain=domain)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = 'parent-995424086'
        region = 'region-934795532'
        domain = {}

        with pytest.raises(CustomException):
            client.create_domain(parent, region, domain)

    def test_update_domain(self):
        # Setup Expected Response
        name = 'name3373707'
        parent = 'parent-995424086'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name,
            'parent': parent,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        domain = {}
        update_mask = {}

        response = client.update_domain(domain, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.UpdateDomainRequest(
            domain=domain, update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        domain = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_domain(domain, update_mask)

    def test_delete_domain(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name_2,
            'parent': parent,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        response = client.delete_domain(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.DeleteDomainRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        with pytest.raises(CustomException):
            client.delete_domain(name)

    def test_undelete_domain(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name_2,
            'parent': parent,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        response = client.undelete_domain(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.UndeleteDomainRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_undelete_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        with pytest.raises(CustomException):
            client.undelete_domain(name)

    def test_test_receipt_rules(self):
        # Setup Expected Response
        catch_all = False
        expected_response = {'catch_all': catch_all}
        expected_response = domain_pb2.TestReceiptRulesResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        domain = client.domain_path('[REGION]', '[DOMAIN]')
        recipient = 'recipient820081177'
        receipt_ruleset = {}

        response = client.test_receipt_rules(domain, recipient,
                                             receipt_ruleset)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.TestReceiptRulesRequest(
            domain=domain,
            recipient=recipient,
            receipt_ruleset=receipt_ruleset)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_test_receipt_rules_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        domain = client.domain_path('[REGION]', '[DOMAIN]')
        recipient = 'recipient820081177'
        receipt_ruleset = {}

        with pytest.raises(CustomException):
            client.test_receipt_rules(domain, recipient, receipt_ruleset)

    def test_verify_domain(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        deleted = False
        domain_name = 'domainName104118566'
        project_domain = True
        verification_token = 'verificationToken-498552107'
        expected_response = {
            'name': name_2,
            'parent': parent,
            'deleted': deleted,
            'domain_name': domain_name,
            'project_domain': project_domain,
            'verification_token': verification_token
        }
        expected_response = domain_pb2.Domain(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        response = client.verify_domain(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = domain_pb2.VerifyDomainRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_verify_domain_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.domain_path('[REGION]', '[DOMAIN]')

        with pytest.raises(CustomException):
            client.verify_domain(name)

    def test_list_email_verified_addresses(self):
        # Setup Expected Response
        expected_response = {}
        expected_response = email_verified_address_pb2.ListEmailVerifiedAddressesResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        show_deleted = False

        response = client.list_email_verified_addresses(
            parent, region, show_deleted)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.ListEmailVerifiedAddressesRequest(
            parent=parent, region=region, show_deleted=show_deleted)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_email_verified_addresses_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        show_deleted = False

        with pytest.raises(CustomException):
            client.list_email_verified_addresses(parent, region, show_deleted)

    def test_get_email_verified_address(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name_2,
            'parent': parent,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        response = client.get_email_verified_address(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.GetEmailVerifiedAddressRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_email_verified_address_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        with pytest.raises(CustomException):
            client.get_email_verified_address(name)

    def test_create_email_verified_address(self):
        # Setup Expected Response
        name = 'name3373707'
        parent_2 = 'parent21175163357'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name,
            'parent': parent_2,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        email_verified_address = {}

        response = client.create_email_verified_address(
            parent, region, email_verified_address)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.CreateEmailVerifiedAddressRequest(
            parent=parent,
            region=region,
            email_verified_address=email_verified_address)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_email_verified_address_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        email_verified_address = {}

        with pytest.raises(CustomException):
            client.create_email_verified_address(parent, region,
                                                 email_verified_address)

    def test_update_email_verified_address(self):
        # Setup Expected Response
        name = 'name3373707'
        parent = 'parent-995424086'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name,
            'parent': parent,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        email_verified_address = {}
        update_mask = {}

        response = client.update_email_verified_address(
            email_verified_address, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.UpdateEmailVerifiedAddressRequest(
            email_verified_address=email_verified_address,
            update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_email_verified_address_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        email_verified_address = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_email_verified_address(email_verified_address,
                                                 update_mask)

    def test_delete_email_verified_address(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name_2,
            'parent': parent,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        response = client.delete_email_verified_address(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.DeleteEmailVerifiedAddressRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_email_verified_address_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        with pytest.raises(CustomException):
            client.delete_email_verified_address(name)

    def test_undelete_email_verified_address(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name_2,
            'parent': parent,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        response = client.undelete_email_verified_address(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.UndeleteEmailVerifiedAddressRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_undelete_email_verified_address_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        with pytest.raises(CustomException):
            client.undelete_email_verified_address(name)

    def test_request_email_verification(self):
        # Setup Expected Response
        rfc822_message_id = 'rfc822MessageId-427623191'
        expected_response = {'rfc822_message_id': rfc822_message_id}
        expected_response = email_verified_address_pb2.RequestEmailVerificationResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        response = client.request_email_verification(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.RequestEmailVerificationRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_request_email_verification_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')

        with pytest.raises(CustomException):
            client.request_email_verification(name)

    def test_verify_email(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        parent = 'parent-995424086'
        address = 'address-1147692044'
        deleted = False
        expected_response = {
            'name': name_2,
            'parent': parent,
            'address': address,
            'deleted': deleted
        }
        expected_response = email_verified_address_pb2.EmailVerifiedAddress(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')
        token = 'token110541305'

        response = client.verify_email(name, token)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = email_verified_address_pb2.VerifyEmailRequest(
            name=name, token=token)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_verify_email_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.email_verified_address_path('[PROJECT]', '[REGION]',
                                                  '[EMAIL_VERIFIED_ADDRESS]')
        token = 'token110541305'

        with pytest.raises(CustomException):
            client.verify_email(name, token)

    def test_list_senders(self):
        # Setup Expected Response
        next_page_token = ''
        senders_element = {}
        senders = [senders_element]
        expected_response = {
            'next_page_token': next_page_token,
            'senders': senders
        }
        expected_response = sender_pb2.ListSendersResponse(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        show_deleted = False

        paged_list_response = client.list_senders(parent, region, show_deleted)
        resources = list(paged_list_response)
        assert len(resources) == 1

        assert expected_response.senders[0] == resources[0]

        assert len(channel.requests) == 1
        expected_request = sender_pb2.ListSendersRequest(
            parent=parent, region=region, show_deleted=show_deleted)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_senders_exception(self):
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        show_deleted = False

        paged_list_response = client.list_senders(parent, region, show_deleted)
        with pytest.raises(CustomException):
            list(paged_list_response)

    def test_get_sender(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        default_envelope_from_authority = 'defaultEnvelopeFromAuthority1550530879'
        default_header_from_authority = 'defaultHeaderFromAuthority-1184297630'
        expected_response = {
            'name': name_2,
            'deleted': deleted,
            'default_envelope_from_authority': default_envelope_from_authority,
            'default_header_from_authority': default_header_from_authority
        }
        expected_response = sender_pb2.Sender(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        response = client.get_sender(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.GetSenderRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_sender_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        with pytest.raises(CustomException):
            client.get_sender(name)

    def test_create_sender(self):
        # Setup Expected Response
        name = 'name3373707'
        deleted = False
        default_envelope_from_authority = 'defaultEnvelopeFromAuthority1550530879'
        default_header_from_authority = 'defaultHeaderFromAuthority-1184297630'
        expected_response = {
            'name': name,
            'deleted': deleted,
            'default_envelope_from_authority': default_envelope_from_authority,
            'default_header_from_authority': default_header_from_authority
        }
        expected_response = sender_pb2.Sender(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        sender_id = 'senderId32190309'
        sender = {}

        response = client.create_sender(parent, region, sender_id, sender)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.CreateSenderRequest(
            parent=parent, region=region, sender_id=sender_id, sender=sender)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_sender_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.project_path('[PROJECT]')
        region = 'region-934795532'
        sender_id = 'senderId32190309'
        sender = {}

        with pytest.raises(CustomException):
            client.create_sender(parent, region, sender_id, sender)

    def test_update_sender(self):
        # Setup Expected Response
        name = 'name3373707'
        deleted = False
        default_envelope_from_authority = 'defaultEnvelopeFromAuthority1550530879'
        default_header_from_authority = 'defaultHeaderFromAuthority-1184297630'
        expected_response = {
            'name': name,
            'deleted': deleted,
            'default_envelope_from_authority': default_envelope_from_authority,
            'default_header_from_authority': default_header_from_authority
        }
        expected_response = sender_pb2.Sender(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        sender = {}
        update_mask = {}

        response = client.update_sender(sender, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.UpdateSenderRequest(
            sender=sender, update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_sender_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        sender = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_sender(sender, update_mask)

    def test_delete_sender(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        default_envelope_from_authority = 'defaultEnvelopeFromAuthority1550530879'
        default_header_from_authority = 'defaultHeaderFromAuthority-1184297630'
        expected_response = {
            'name': name_2,
            'deleted': deleted,
            'default_envelope_from_authority': default_envelope_from_authority,
            'default_header_from_authority': default_header_from_authority
        }
        expected_response = sender_pb2.Sender(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        response = client.delete_sender(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.DeleteSenderRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_sender_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        with pytest.raises(CustomException):
            client.delete_sender(name)

    def test_undelete_sender(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        default_envelope_from_authority = 'defaultEnvelopeFromAuthority1550530879'
        default_header_from_authority = 'defaultHeaderFromAuthority-1184297630'
        expected_response = {
            'name': name_2,
            'deleted': deleted,
            'default_envelope_from_authority': default_envelope_from_authority,
            'default_header_from_authority': default_header_from_authority
        }
        expected_response = sender_pb2.Sender(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        response = client.undelete_sender(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.UndeleteSenderRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_undelete_sender_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        with pytest.raises(CustomException):
            client.undelete_sender(name)

    def test_send_message(self):
        # Setup Expected Response
        rfc822_message_id = 'rfc822MessageId-427623191'
        expected_response = {'rfc822_message_id': rfc822_message_id}
        expected_response = sender_pb2.SendMessageResponse(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        sender = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
        envelope_from_authority = 'envelopeFromAuthority-735981251'
        header_from_authority = 'headerFromAuthority-985559840'
        envelope_from_address = 'envelopeFromAddress1388551278'

        response = client.send_message(sender, envelope_from_authority,
                                       header_from_authority,
                                       envelope_from_address)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = sender_pb2.SendMessageRequest(
            sender=sender,
            envelope_from_authority=envelope_from_authority,
            header_from_authority=header_from_authority,
            envelope_from_address=envelope_from_address)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_send_message_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        sender = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
        envelope_from_authority = 'envelopeFromAuthority-735981251'
        header_from_authority = 'headerFromAuthority-985559840'
        envelope_from_address = 'envelopeFromAddress1388551278'

        with pytest.raises(CustomException):
            client.send_message(sender, envelope_from_authority,
                                header_from_authority, envelope_from_address)

    def test_list_smtp_credentials(self):
        # Setup Expected Response
        expected_response = {}
        expected_response = smtp_credential_pb2.ListSmtpCredentialsResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        response = client.list_smtp_credentials(parent)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = smtp_credential_pb2.ListSmtpCredentialsRequest(
            parent=parent)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_smtp_credentials_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')

        with pytest.raises(CustomException):
            client.list_smtp_credentials(parent)

    def test_get_smtp_credential(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        user_id = 'userId-147132913'
        password = 'password1216985755'
        service_account_name = 'serviceAccountName235400871'
        service_account_email = 'serviceAccountEmail-1300473088'
        expected_response = {
            'name': name_2,
            'user_id': user_id,
            'password': password,
            'service_account_name': service_account_name,
            'service_account_email': service_account_email
        }
        expected_response = smtp_credential_pb2.SmtpCredential(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]',
                                           '[SMTP_CREDENTIAL]')

        response = client.get_smtp_credential(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = smtp_credential_pb2.GetSmtpCredentialRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_smtp_credential_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]',
                                           '[SMTP_CREDENTIAL]')

        with pytest.raises(CustomException):
            client.get_smtp_credential(name)

    def test_create_smtp_credential(self):
        # Setup Expected Response
        name = 'name3373707'
        user_id = 'userId-147132913'
        password = 'password1216985755'
        service_account_name = 'serviceAccountName235400871'
        service_account_email = 'serviceAccountEmail-1300473088'
        expected_response = {
            'name': name,
            'user_id': user_id,
            'password': password,
            'service_account_name': service_account_name,
            'service_account_email': service_account_email
        }
        expected_response = smtp_credential_pb2.SmtpCredential(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
        smtp_credential_id = 'smtpCredentialId-1531115558'
        smtp_credential = {}

        response = client.create_smtp_credential(parent, smtp_credential_id,
                                                 smtp_credential)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = smtp_credential_pb2.CreateSmtpCredentialRequest(
            parent=parent,
            smtp_credential_id=smtp_credential_id,
            smtp_credential=smtp_credential)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_smtp_credential_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.sender_path('[PROJECT]', '[REGION]', '[SENDER]')
        smtp_credential_id = 'smtpCredentialId-1531115558'
        smtp_credential = {}

        with pytest.raises(CustomException):
            client.create_smtp_credential(parent, smtp_credential_id,
                                          smtp_credential)

    def test_update_smtp_credential(self):
        # Setup Expected Response
        name = 'name3373707'
        user_id = 'userId-147132913'
        password = 'password1216985755'
        service_account_name = 'serviceAccountName235400871'
        service_account_email = 'serviceAccountEmail-1300473088'
        expected_response = {
            'name': name,
            'user_id': user_id,
            'password': password,
            'service_account_name': service_account_name,
            'service_account_email': service_account_email
        }
        expected_response = smtp_credential_pb2.SmtpCredential(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        smtp_credential = {}
        update_mask = {}

        response = client.update_smtp_credential(smtp_credential, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = smtp_credential_pb2.UpdateSmtpCredentialRequest(
            smtp_credential=smtp_credential, update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_smtp_credential_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        smtp_credential = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_smtp_credential(smtp_credential, update_mask)

    def test_delete_smtp_credential(self):
        channel = ChannelStub()
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]',
                                           '[SMTP_CREDENTIAL]')

        client.delete_smtp_credential(name)

        assert len(channel.requests) == 1
        expected_request = smtp_credential_pb2.DeleteSmtpCredentialRequest(
            name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_smtp_credential_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.smtp_credential_path('[PROJECT]', '[REGION]', '[SENDER]',
                                           '[SMTP_CREDENTIAL]')

        with pytest.raises(CustomException):
            client.delete_smtp_credential(name)

    def test_list_receipt_rules(self):
        # Setup Expected Response
        next_page_token = ''
        total_size = 705419236
        receipt_rules_element = {}
        receipt_rules = [receipt_rules_element]
        expected_response = {
            'next_page_token': next_page_token,
            'total_size': total_size,
            'receipt_rules': receipt_rules
        }
        expected_response = receipt_rule_pb2.ListReceiptRulesResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.domain_path('[REGION]', '[DOMAIN]')

        paged_list_response = client.list_receipt_rules(parent)
        resources = list(paged_list_response)
        assert len(resources) == 1

        assert expected_response.receipt_rules[0] == resources[0]

        assert len(channel.requests) == 1
        expected_request = receipt_rule_pb2.ListReceiptRulesRequest(
            parent=parent)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_receipt_rules_exception(self):
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.domain_path('[REGION]', '[DOMAIN]')

        paged_list_response = client.list_receipt_rules(parent)
        with pytest.raises(CustomException):
            list(paged_list_response)

    def test_get_receipt_rule(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        expected_response = {'name': name_2}
        expected_response = receipt_rule_pb2.ReceiptRule(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.receipt_rule_path('[REGION]', '[DOMAIN]',
                                        '[RECEIPT_RULE]')

        response = client.get_receipt_rule(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = receipt_rule_pb2.GetReceiptRuleRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_receipt_rule_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.receipt_rule_path('[REGION]', '[DOMAIN]',
                                        '[RECEIPT_RULE]')

        with pytest.raises(CustomException):
            client.get_receipt_rule(name)

    def test_create_receipt_rule(self):
        # Setup Expected Response
        name = 'name3373707'
        expected_response = {'name': name}
        expected_response = receipt_rule_pb2.ReceiptRule(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        rule_id = 'ruleId1548659006'
        receipt_rule = {}

        response = client.create_receipt_rule(parent, rule_id, receipt_rule)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = receipt_rule_pb2.CreateReceiptRuleRequest(
            parent=parent, rule_id=rule_id, receipt_rule=receipt_rule)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_receipt_rule_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        rule_id = 'ruleId1548659006'
        receipt_rule = {}

        with pytest.raises(CustomException):
            client.create_receipt_rule(parent, rule_id, receipt_rule)

    def test_update_receipt_rule(self):
        # Setup Expected Response
        name = 'name3373707'
        expected_response = {'name': name}
        expected_response = receipt_rule_pb2.ReceiptRule(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        receipt_rule = {}
        update_mask = {}

        response = client.update_receipt_rule(receipt_rule, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = receipt_rule_pb2.UpdateReceiptRuleRequest(
            receipt_rule=receipt_rule, update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_receipt_rule_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        receipt_rule = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_receipt_rule(receipt_rule, update_mask)

    def test_delete_receipt_rule(self):
        channel = ChannelStub()
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.receipt_rule_path('[REGION]', '[DOMAIN]',
                                        '[RECEIPT_RULE]')

        client.delete_receipt_rule(name)

        assert len(channel.requests) == 1
        expected_request = receipt_rule_pb2.DeleteReceiptRuleRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_receipt_rule_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.receipt_rule_path('[REGION]', '[DOMAIN]',
                                        '[RECEIPT_RULE]')

        with pytest.raises(CustomException):
            client.delete_receipt_rule(name)

    def test_list_address_sets(self):
        # Setup Expected Response
        expected_response = {}
        expected_response = address_set_pb2.ListAddressSetsResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        show_deleted = False

        response = client.list_address_sets(parent, show_deleted)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.ListAddressSetsRequest(
            parent=parent, show_deleted=show_deleted)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_list_address_sets_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        show_deleted = False

        with pytest.raises(CustomException):
            client.list_address_sets(parent, show_deleted)

    def test_get_address_set(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        expected_response = {'name': name_2, 'deleted': deleted}
        expected_response = address_set_pb2.AddressSet(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        response = client.get_address_set(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.GetAddressSetRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_address_set_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        with pytest.raises(CustomException):
            client.get_address_set(name)

    def test_create_address_set(self):
        # Setup Expected Response
        name = 'name3373707'
        deleted = False
        expected_response = {'name': name, 'deleted': deleted}
        expected_response = address_set_pb2.AddressSet(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        address_set_id = 'addressSetId549816515'
        address_set = {}

        response = client.create_address_set(parent, address_set_id,
                                             address_set)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.CreateAddressSetRequest(
            parent=parent,
            address_set_id=address_set_id,
            address_set=address_set)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_create_address_set_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        parent = client.domain_path('[REGION]', '[DOMAIN]')
        address_set_id = 'addressSetId549816515'
        address_set = {}

        with pytest.raises(CustomException):
            client.create_address_set(parent, address_set_id, address_set)

    def test_update_address_set(self):
        # Setup Expected Response
        name = 'name3373707'
        deleted = False
        expected_response = {'name': name, 'deleted': deleted}
        expected_response = address_set_pb2.AddressSet(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        address_set = {}
        update_mask = {}

        response = client.update_address_set(address_set, update_mask)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.UpdateAddressSetRequest(
            address_set=address_set, update_mask=update_mask)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_update_address_set_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        address_set = {}
        update_mask = {}

        with pytest.raises(CustomException):
            client.update_address_set(address_set, update_mask)

    def test_delete_address_set(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        expected_response = {'name': name_2, 'deleted': deleted}
        expected_response = address_set_pb2.AddressSet(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        response = client.delete_address_set(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.DeleteAddressSetRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_delete_address_set_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        with pytest.raises(CustomException):
            client.delete_address_set(name)

    def test_undelete_address_set(self):
        # Setup Expected Response
        name_2 = 'name2-1052831874'
        deleted = False
        expected_response = {'name': name_2, 'deleted': deleted}
        expected_response = address_set_pb2.AddressSet(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        response = client.undelete_address_set(name)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = address_set_pb2.UndeleteAddressSetRequest(name=name)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_undelete_address_set_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        name = client.address_set_path('[REGION]', '[DOMAIN]', '[ADDRESS_SET]')

        with pytest.raises(CustomException):
            client.undelete_address_set(name)

    def test_get_iam_policy(self):
        # Setup Expected Response
        version = 351608024
        etag = b'21'
        expected_response = {'version': version, 'etag': etag}
        expected_response = policy_pb2.Policy(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        resource = client.domain_path('[REGION]', '[DOMAIN]')

        response = client.get_iam_policy(resource)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = iam_policy_pb2.GetIamPolicyRequest(
            resource=resource)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_get_iam_policy_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        resource = client.domain_path('[REGION]', '[DOMAIN]')

        with pytest.raises(CustomException):
            client.get_iam_policy(resource)

    def test_set_iam_policy(self):
        # Setup Expected Response
        version = 351608024
        etag = b'21'
        expected_response = {'version': version, 'etag': etag}
        expected_response = policy_pb2.Policy(**expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        resource = client.domain_path('[REGION]', '[DOMAIN]')
        policy = {}

        response = client.set_iam_policy(resource, policy)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = iam_policy_pb2.SetIamPolicyRequest(
            resource=resource, policy=policy)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_set_iam_policy_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        resource = client.domain_path('[REGION]', '[DOMAIN]')
        policy = {}

        with pytest.raises(CustomException):
            client.set_iam_policy(resource, policy)

    def test_test_iam_permissions(self):
        # Setup Expected Response
        expected_response = {}
        expected_response = iam_policy_pb2.TestIamPermissionsResponse(
            **expected_response)

        # Mock the API response
        channel = ChannelStub(responses=[expected_response])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup Request
        resource = client.domain_path('[REGION]', '[DOMAIN]')
        permissions = []

        response = client.test_iam_permissions(resource, permissions)
        assert expected_response == response

        assert len(channel.requests) == 1
        expected_request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=resource, permissions=permissions)
        actual_request = channel.requests[0][1]
        assert expected_request == actual_request

    def test_test_iam_permissions_exception(self):
        # Mock the API response
        channel = ChannelStub(responses=[CustomException()])
        client = mail_v1alpha3.CloudMailClient(channel=channel)

        # Setup request
        resource = client.domain_path('[REGION]', '[DOMAIN]')
        permissions = []

        with pytest.raises(CustomException):
            client.test_iam_permissions(resource, permissions)

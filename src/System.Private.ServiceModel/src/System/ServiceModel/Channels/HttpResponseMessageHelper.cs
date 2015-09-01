﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.Contracts;
using System.IO;
using System.Net;
using System.Net.Http;
using System.ServiceModel.Diagnostics.Application;
using System.ServiceModel.Security;
using System.Threading.Tasks;
using System.Xml;

namespace System.ServiceModel.Channels
{
    internal class HttpResponseMessageHelper
    {
        private readonly HttpChannelFactory<IRequestChannel> _factory;
        private readonly MessageEncoder _encoder;
        private readonly HttpRequestMessage _httpRequestMessage;
        private readonly HttpResponseMessage _httpResponseMessage;
        private string _contentType;
        private long _contentLength;

        public HttpResponseMessageHelper(HttpResponseMessage httpResponseMessage, HttpChannelFactory<IRequestChannel> factory)
        {
            Contract.Assert(httpResponseMessage != null);
            Contract.Assert(httpResponseMessage.RequestMessage != null);
            Contract.Assert(factory != null);
            _httpResponseMessage = httpResponseMessage;
            _httpRequestMessage = httpResponseMessage.RequestMessage;
            _factory = factory;
            _encoder = factory.MessageEncoderFactory.Encoder;
        }

        internal async Task<Message> ParseIncomingResponse()
        {
            ValidateAuthentication();
            ValidateResponseStatusCode();
            bool hasContent = await ValidateContentTypeAsync();
            Message message = null;

            if (!hasContent)
            {
                if (_encoder.MessageVersion == MessageVersion.None)
                {
                    message = new NullMessage();
                }
                else
                {
                    return null;
                }
            }
            else
            {
                message = await ReadStreamAsMessageAsync();
            }

            var exception = ProcessHttpAddressing(message);
            Contract.Assert(exception == null, "ProcessHttpAddressing should not set an exception after parsing a response message.");

            return message;
        }

        private Exception ProcessHttpAddressing(Message message)
        {
            Exception result = null;
            AddProperties(message);

            // check if user is receiving WS-1 messages
            if (message.Version.Addressing == AddressingVersion.None)
            {
                bool actionAbsent = false;
                try
                {
                    actionAbsent = (message.Headers.Action == null);
                    // message.Headers.Action uses an XmlDictionaryReader. If the xml is malformed,
                    // an XmlException might be thrown when trying to parse the response data.
                    // CommunicationException is the base type for any ServiceModel exceptions. If anything went
                    // wrong in any ServiceModel code, an exception deriving from CommunicationException will be
                    // thrown. 
                    // In these cases, be tolerant of the failure and treat it as though the action is absent.
                }
                catch (XmlException)
                {
                }
                catch (CommunicationException)
                {
                }
                if (!actionAbsent)
                {
                    result = new ProtocolException(SR.Format(SR.HttpAddressingNoneHeaderOnWire,
                        XD.AddressingDictionary.Action.Value));
                }

                bool toAbsent = false;
                try
                {
                    toAbsent = (message.Headers.To == null);
                    // message.Headers.To has the same failure modes as for the Action header.
                }
                catch (XmlException)
                {
                }
                catch (CommunicationException)
                {
                }

                if (!toAbsent)
                {
                    result = new ProtocolException(SR.Format(SR.HttpAddressingNoneHeaderOnWire,
                        XD.AddressingDictionary.To.Value));
                }
                message.Headers.To = message.Properties.Via;
            }

            return result;
        }

        private void AddProperties(Message message)
        {
            HttpResponseMessageProperty responseProperty = new HttpResponseMessageProperty(_httpResponseMessage);
            message.Properties.Add(HttpResponseMessageProperty.Name, responseProperty);
            message.Properties.Via = message.Version.Addressing.AnonymousUri;
        }

        private async Task<bool> ValidateContentTypeAsync()
        {
            var content = _httpResponseMessage.Content;
            if (content != null)
            {
                var mediaValueContentType = content.Headers.ContentType;
                _contentType = mediaValueContentType == null ? string.Empty : mediaValueContentType.ToString();
                _contentLength = content.Headers.ContentLength.HasValue ? content.Headers.ContentLength.Value : -1;
            }

            if (string.IsNullOrEmpty(_contentType))
            {
                Stream contentStream = await GetStreamAsync();
                if (contentStream != null)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ProtocolException(SR.HttpContentTypeHeaderRequired));
                }
                return false;
            }
            else if (_contentLength != 0)
            {
                if (!_encoder.IsContentTypeSupported(_contentType))
                {
                    int bytesToRead = (int)_contentLength;
                    Stream contentStream = await GetStreamAsync();
                    string responseExcerpt = HttpChannelUtilities.GetResponseStreamExcerptString(contentStream, ref bytesToRead);
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(HttpChannelUtilities.TraceResponseException(
                        new ProtocolException(
                            SR.Format(
                                SR.ResponseContentTypeMismatch,
                                _contentType,
                                _encoder.ContentType,
                                bytesToRead,
                                responseExcerpt))));
                }
            }
            return true;
        }

        private async Task<Message> ReadStreamAsMessageAsync()
        {
            var content = _httpResponseMessage.Content;
            Message message = null;
            Stream contentStream = await GetStreamAsync();

            if (TransferModeHelper.IsResponseStreamed(_factory.TransferMode))
            {
                message = ReadStreamedMessage(contentStream);
            }
            else if (!content.Headers.ContentLength.HasValue)
            {
                message = ReadChunkedBufferedMessage(contentStream);
            }
            else
            {
                message = await ReadBufferedMessageAsync(contentStream);
            }
            return message;
        }

        private Message ReadChunkedBufferedMessage(Stream inputStream)
        {
            try
            {
                return _encoder.ReadMessage(inputStream, _factory.BufferManager, _factory.MaxBufferSize, _contentType);
            }
            catch (XmlException xmlException)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                    new ProtocolException(SR.MessageXmlProtocolError, xmlException));
            }
        }

        private async Task<Message> ReadBufferedMessageAsync(Stream inputStream)
        {
            if (_contentLength > _factory.MaxReceivedMessageSize)
            {
                ThrowMaxReceivedMessageSizeExceeded();
            }

            int bufferSize = (int)_contentLength;

            var messageBuffer = new ArraySegment<byte>(_factory.BufferManager.TakeBuffer(bufferSize), 0, bufferSize);

            byte[] buffer = messageBuffer.Array;
            int offset = 0;
            int count = messageBuffer.Count;

            while (count > 0)
            {
                int bytesRead = await inputStream.ReadAsync(buffer, offset, count);
                if (bytesRead == 0) // EOF 
                {
                    if (_contentLength != -1)
                    {
                        throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                            new ProtocolException(SR.HttpContentLengthIncorrect));
                    }

                    break;
                }
                count -= bytesRead;
                offset += bytesRead;
            }

            return await DecodeBufferedMessageAsync(new ArraySegment<byte>(buffer, 0, offset), inputStream);
        }

        private Message ReadStreamedMessage(Stream inputStream)
        {
            MaxMessageSizeStream maxMessageSizeStream = new MaxMessageSizeStream(inputStream, _factory.MaxReceivedMessageSize);

            try
            {
                return _encoder.ReadMessage(maxMessageSizeStream, _factory.MaxBufferSize, _contentType);
            }
            catch (XmlException xmlException)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                    new ProtocolException(SR.MessageXmlProtocolError, xmlException));
            }
        }

        private void ThrowMaxReceivedMessageSizeExceeded()
        {
            if (TD.MaxReceivedMessageSizeExceededIsEnabled())
            {
                TD.MaxReceivedMessageSizeExceeded(SR.Format(SR.MaxReceivedMessageSizeExceeded, _factory.MaxReceivedMessageSize));
            }

            string message = SR.Format(SR.MaxReceivedMessageSizeExceeded, _factory.MaxReceivedMessageSize);
            Exception inner = new QuotaExceededException(message);
            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new CommunicationException(message, inner));
        }

        private async Task<Message> DecodeBufferedMessageAsync(ArraySegment<byte> buffer, Stream inputStream)
        {
            try
            {
                // if we're chunked, make sure we've consumed the whole body
                if (_contentLength == -1 && buffer.Count == _factory.MaxReceivedMessageSize)
                {
                    byte[] extraBuffer = new byte[1];
                    int extraReceived = await inputStream.ReadAsync(extraBuffer, 0, 1);
                    if (extraReceived > 0)
                    {
                        ThrowMaxReceivedMessageSizeExceeded();
                    }
                }

                try
                {
                    return _encoder.ReadMessage(buffer, _factory.BufferManager, _contentType);
                }
                catch (XmlException xmlException)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                        new ProtocolException(SR.MessageXmlProtocolError, xmlException));
                }
            }
            finally
            {
                inputStream.Dispose();
            }
        }

        private async Task<Stream> GetStreamAsync()
        {
            var content = _httpResponseMessage.Content;
            Stream contentStream = null;
            _contentLength = -1;
            if (content != null)
            {
                contentStream = await content.ReadAsStreamAsync();
                _contentLength = content.Headers.ContentLength.HasValue ? content.Headers.ContentLength.Value : -1;
                if (_contentLength <= 0)
                {
                    var preReadBuffer = new byte[1];
                    if (await contentStream.ReadAsync(preReadBuffer, 0, 1) == 0)
                    {
                        preReadBuffer = null;
                        contentStream.Dispose();
                        contentStream = null;
                    }
                    else
                    {
                        contentStream = new PreReadStream(contentStream, preReadBuffer);
                    }
                }
            }

            return contentStream;
        }

        private void ValidateResponseStatusCode()
        {
            if (((int)_httpResponseMessage.StatusCode < 200 || (int)_httpResponseMessage.StatusCode >= 300) && _httpResponseMessage.StatusCode != HttpStatusCode.InternalServerError)
            {
                if (_httpResponseMessage.StatusCode == HttpStatusCode.NotFound)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new EndpointNotFoundException(SR.Format(SR.EndpointNotFound, _httpRequestMessage.RequestUri.AbsoluteUri)));
                }

                if (_httpResponseMessage.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ServerTooBusyException(SR.Format(SR.HttpServerTooBusy, _httpRequestMessage.RequestUri.AbsoluteUri)));
                }

                if (_httpResponseMessage.StatusCode == HttpStatusCode.UnsupportedMediaType)
                {
                    string statusDescription = _httpResponseMessage.ReasonPhrase;
                    if (!string.IsNullOrEmpty(statusDescription))
                    {
                        if (string.Compare(statusDescription, HttpChannelUtilities.StatusDescriptionStrings.HttpContentTypeMissing, StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ProtocolException(SR.Format(SR.MissingContentType, _httpRequestMessage.RequestUri)));
                        }
                    }
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ProtocolException(SR.Format(SR.FramingContentTypeMismatch, _httpRequestMessage.Content.Headers.ContentType.ToString(), _httpRequestMessage.RequestUri)));
                }

                if (_httpResponseMessage.StatusCode == HttpStatusCode.GatewayTimeout)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new TimeoutException(_httpResponseMessage.StatusCode + " " + _httpResponseMessage.ReasonPhrase));
                }

                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(HttpChannelUtilities.CreateUnexpectedResponseException(_httpResponseMessage));
            }
        }

        private void ValidateAuthentication()
        {
            if (_httpResponseMessage.StatusCode == HttpStatusCode.Unauthorized)
            {
                string message = SR.Format(SR.HttpAuthorizationFailed, _factory.AuthenticationScheme,
                    _httpResponseMessage.Headers.WwwAuthenticate.ToString());
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                    HttpChannelUtilities.TraceResponseException(new MessageSecurityException(message)));
            }

            if (_httpResponseMessage.StatusCode == HttpStatusCode.Forbidden)
            {
                string message = SR.Format(SR.HttpAuthorizationForbidden, _factory.AuthenticationScheme);
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(
                    HttpChannelUtilities.TraceResponseException(new MessageSecurityException(message)));
            }
        }
    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace WcfService.TestResources
{
    internal class TcpTransportSecurityWithSslResource : TcpResource
    {
        protected override string Address { get { return "tcp-server-ssl-security"; } }

        protected override Binding GetBinding()
        {
            return new CustomBinding(
                new SslStreamSecurityBindingElement(),
                new BinaryMessageEncodingBindingElement(),
                new TcpTransportBindingElement()
                );
        }

        protected override void ModifyHost(ServiceHost serviceHost)
        {
            serviceHost.Credentials.ServiceCertificate.SetCertificate(StoreLocation.LocalMachine,
                                                      StoreName.My,
                                                      X509FindType.FindByThumbprint,
                                                      certThumbprint);
        }

    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.IdentityModel.Selectors
{
    using System.IdentityModel.Configuration;
    using System.Security.Cryptography.X509Certificates;
    using ServiceModel;

    public abstract class X509CertificateValidator : ICustomIdentityConfiguration
    {
        static X509CertificateValidator chainTrust;
        static X509CertificateValidator none;

        public static X509CertificateValidator None
        {
            get
            {
                if (none == null)
                    none = new NoneX509CertificateValidator();
                return none;
            }
        }
        public static X509CertificateValidator ChainTrust
        {
            get
            {
                if (chainTrust == null)
                    chainTrust = new ChainTrustValidator();
                return chainTrust;
            }
        }
        
        public abstract void Validate(X509Certificate2 certificate);

        class NoneX509CertificateValidator : X509CertificateValidator
        {
            public override void Validate(X509Certificate2 certificate)
            {
                if (certificate == null)
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("certificate");
            }
        }

        class ChainTrustValidator : X509CertificateValidator
        {

            public ChainTrustValidator()
            {
            }

            public override void Validate(X509Certificate2 certificate)
            {
                // TODO: jasonpa
                throw new PlatformNotSupportedException(); 
            }
        }
    }
}

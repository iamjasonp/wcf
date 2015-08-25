// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.IdentityModel.Selectors
{
    using System.IdentityModel.Configuration;
    using System.Security.Cryptography.X509Certificates;
    using Text;
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

        public static X509CertificateValidator CreateChainTrustValidator(bool useMachineContext, X509ChainPolicy chainPolicy)
        {
            if (chainPolicy == null)
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("chainPolicy");
            return new ChainTrustValidator(useMachineContext, chainPolicy, X509CertificateChain.DefaultChainPolicyOID);
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
            bool _useMachineContext;
            X509ChainPolicy _chainPolicy;
            uint _chainPolicyOID = X509CertificateChain.DefaultChainPolicyOID;

            public ChainTrustValidator()
            {
                _chainPolicy = null;
            }

            public ChainTrustValidator(bool useMachineContext, X509ChainPolicy chainPolicy, uint chainPolicyOID)
            {
                _useMachineContext = useMachineContext;
                _chainPolicy = chainPolicy;
                _chainPolicyOID = chainPolicyOID;
            }

            public override void Validate(X509Certificate2 certificate)
            {
                if (certificate == null)
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("certificate");

                // TODO: jasonpa: check on this
                // X509Chain chain = new X509Chain(_useMachineContext, _chainPolicyOID);
                X509Chain chain = new X509Chain(); 

                if (_chainPolicy != null)
                {
                    chain.ChainPolicy = _chainPolicy;
                }

                if (!chain.Build(certificate))
                {
                    // TODO: jasonpa, check on this 
                    throw new NotImplementedException("not real, need a real exception message, old one nuked");
                    //throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityTokenValidationException(SR.Format(SR.X509ChainBuildFail,
                    //    SecurityUtils.GetCertificateId(certificate), GetChainStatusInformation(chain.ChainStatus))));
                }
            }

            static string GetChainStatusInformation(X509ChainStatus[] chainStatus)
            {
                if (chainStatus != null)
                {
                    StringBuilder error = new StringBuilder(128);
                    for (int i = 0; i < chainStatus.Length; ++i)
                    {
                        error.Append(chainStatus[i].StatusInformation);
                        error.Append(" ");
                    }
                    return error.ToString();
                }
                return String.Empty;
            }
        }
    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if FEATURE_CORECLR // X509Certificate
namespace System.IdentityModel.Selectors
{
    internal class X509CertificateChain
    {
        public const uint DefaultChainPolicyOID = 0x1; // CAPI.CERT_CHAIN_POLICY_BASE
    }
}
#endif

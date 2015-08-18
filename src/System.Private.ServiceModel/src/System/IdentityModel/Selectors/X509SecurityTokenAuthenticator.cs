// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.IdentityModel.Selectors
{
    using Collections.ObjectModel;
    using Policy;
    using Tokens;
    using ServiceModel;

    public class X509SecurityTokenAuthenticator : SecurityTokenAuthenticator
    {
        X509CertificateValidator validator;
        bool mapToWindows;
        bool includeWindowsGroups;
        bool cloneHandle;

        public X509SecurityTokenAuthenticator()
            : this(X509CertificateValidator.ChainTrust)
        {
        }

        public X509SecurityTokenAuthenticator(X509CertificateValidator validator)
            : this(validator, false)
        {
        }

        public X509SecurityTokenAuthenticator(X509CertificateValidator validator, bool mapToWindows)
            : this(validator, mapToWindows, /* WindowsClaimSet.DefaultIncludeWindowsGroups */ true)
        {
        }

        public X509SecurityTokenAuthenticator(X509CertificateValidator validator, bool mapToWindows, bool includeWindowsGroups)
            : this(validator, mapToWindows, includeWindowsGroups, true)
        {
        }

        internal X509SecurityTokenAuthenticator(X509CertificateValidator validator, bool mapToWindows, bool includeWindowsGroups, bool cloneHandle)
        {
            if (validator == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("validator");
            }

            this.validator = validator;
            this.mapToWindows = mapToWindows;
            this.includeWindowsGroups = includeWindowsGroups;
            this.cloneHandle = cloneHandle;
        }

        protected override bool CanValidateTokenCore(SecurityToken token)
        {
            // TODO: jasonpa
            throw new PlatformNotSupportedException(); 
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecurityToken token)
        {
            // TODO: jasonpa
            throw new PlatformNotSupportedException();
        }
    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Tokens;
using System.ServiceModel;

namespace System.IdentityModel.Selectors
{
    public class X509SecurityTokenAuthenticator : SecurityTokenAuthenticator
    {
#if FEATURE_CORECLR // X509Certificate
        private X509CertificateValidator _validator;
        private bool _mapToWindows;
        private bool _includeWindowsGroups;
        private bool _cloneHandle;

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

            _validator = validator;
            _mapToWindows = mapToWindows;
            _includeWindowsGroups = includeWindowsGroups;
            _cloneHandle = cloneHandle;
        }
#endif // FEATURE_CORECLR

        protected override bool CanValidateTokenCore(SecurityToken token)
        {
            throw ExceptionHelper.PlatformNotSupported("X509SecurityTokenAuthenticator.CanValidateTokenCore");
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecurityToken token)
        {
            throw ExceptionHelper.PlatformNotSupported("X509SecurityTokenAuthenticator.ValidateTokenCore");
        }
    }
}


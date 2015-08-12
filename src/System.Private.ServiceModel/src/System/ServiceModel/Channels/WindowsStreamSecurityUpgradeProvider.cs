// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.ServiceModel.Channels
{
    using System.Collections.ObjectModel;
    using System.IdentityModel.Policy;
    using System.IdentityModel.Selectors;
    using System.IdentityModel.Tokens;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Runtime;
    using System.Security.Authentication;
    using System.Security.Principal;
    using System.ServiceModel;
    using System.ServiceModel.Description;
    using System.ServiceModel.Diagnostics.Application;
    using System.ServiceModel.Security;

    class WindowsStreamSecurityUpgradeProvider : StreamSecurityUpgradeProvider
    {
        bool _extractGroupsForWindowsAccounts;
        EndpointIdentity _identity;
        IdentityVerifier _identityVerifier;
        ProtectionLevel _protectionLevel;
        SecurityTokenManager _securityTokenManager;
        NetworkCredential _serverCredential;
        string _scheme;

        public WindowsStreamSecurityUpgradeProvider(WindowsStreamSecurityBindingElement bindingElement, BindingContext context)
            : base(context.Binding)
        {
            this._extractGroupsForWindowsAccounts = TransportDefaults.ExtractGroupsForWindowsAccounts;
            this._protectionLevel = bindingElement.ProtectionLevel;
            this._scheme = context.Binding.Scheme;

            SecurityCredentialsManager credentialProvider = context.BindingParameters.Find<SecurityCredentialsManager>();
            if (credentialProvider == null)
            {
                credentialProvider = ClientCredentials.CreateDefaultCredentials();
            }
            
            this._securityTokenManager = credentialProvider.CreateSecurityTokenManager();
        }

        public string Scheme
        {
            get { return this._scheme; }
        }

        internal bool ExtractGroupsForWindowsAccounts
        {
            get
            {
                return this._extractGroupsForWindowsAccounts;
            }
        }

        public override EndpointIdentity Identity
        {
            get
            {
                // If the server credential is null, then we have not been opened yet and have no identity to expose.
                if (this._serverCredential != null)
                {
                    if (this._identity == null)
                    {
                        lock (ThisLock)
                        {
                            if (this._identity == null)
                            {
                                this._identity = SecurityUtils.CreateWindowsIdentity(this._serverCredential);
                            }
                        }
                    }
                }
                return this._identity;
            }
        }

        internal IdentityVerifier IdentityVerifier
        {
            get
            {
                return this._identityVerifier;
            }
        }

        public ProtectionLevel ProtectionLevel
        {
            get
            {
                return _protectionLevel;
            }
        }

        NetworkCredential ServerCredential
        {
            get
            {
                return this._serverCredential;
            }
        }

        public override StreamUpgradeAcceptor CreateUpgradeAcceptor()
        {
            throw new PlatformNotSupportedException("CreateUpgradeAcceptor"); 
        }

        public override StreamUpgradeInitiator CreateUpgradeInitiator(EndpointAddress remoteAddress, Uri via)
        {
            ThrowIfDisposedOrNotOpen();
            return new WindowsStreamSecurityUpgradeInitiator(this, remoteAddress, via);
        }

        protected override void OnAbort()
        {
        }

        protected override void OnClose(TimeSpan timeout)
        {
        }

        protected override IAsyncResult OnBeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return new CompletedAsyncResult(callback, state);
        }

        protected override void OnEndClose(IAsyncResult result)
        {
            CompletedAsyncResult.End(result);
        }

        protected override void OnOpen(TimeSpan timeout)
        {
        }

        protected override IAsyncResult OnBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            OnOpen(timeout);
            return new CompletedAsyncResult(callback, state);
        }

        protected override void OnEndOpen(IAsyncResult result)
        {
            CompletedAsyncResult.End(result);
        }

        protected override void OnOpened()
        {
            base.OnOpened();

            if (this._identityVerifier == null)
            {
                this._identityVerifier = IdentityVerifier.CreateDefault();
            }

            if (this._serverCredential == null)
            {
                this._serverCredential = CredentialCache.DefaultNetworkCredentials;
            }
        }

        class WindowsStreamSecurityUpgradeInitiator : StreamSecurityUpgradeInitiatorBase
        {
            WindowsStreamSecurityUpgradeProvider parent;
            IdentityVerifier identityVerifier;
            NetworkCredential credential;
            TokenImpersonationLevel impersonationLevel;
            SspiSecurityTokenProvider clientTokenProvider;
            bool allowNtlm;

            public WindowsStreamSecurityUpgradeInitiator(
                WindowsStreamSecurityUpgradeProvider parent, EndpointAddress remoteAddress, Uri via)
                : base(FramingUpgradeString.Negotiate, remoteAddress, via)
            {
                this.parent = parent;
                this.clientTokenProvider = TransportSecurityHelpers.GetSspiTokenProvider(
                    parent._securityTokenManager, remoteAddress, via, parent.Scheme, out this.identityVerifier);
            }

            IAsyncResult BaseBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
            {
                return base.BeginOpen(timeout, callback, state);
            }

            void BaseEndOpen(IAsyncResult result)
            {
                base.EndOpen(result);
            }

            internal override IAsyncResult BeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
            {
                throw new PlatformNotSupportedException("BeginOpen to be implemented");
            }

            internal override void EndOpen(IAsyncResult result)
            {
                throw new PlatformNotSupportedException("EndOpen to be implemented");
            }

            internal override void Open(TimeSpan timeout)
            {
                TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
                base.Open(timeoutHelper.RemainingTime());
                SecurityUtils.OpenTokenProviderIfRequired(this.clientTokenProvider, timeoutHelper.RemainingTime());
                this.credential = TransportSecurityHelpers.GetSspiCredential(this.clientTokenProvider, timeoutHelper.RemainingTime(),
                    out this.impersonationLevel, out this.allowNtlm);
            }

            IAsyncResult BaseBeginClose(TimeSpan timeout, AsyncCallback callback, object state)
            {
                return base.BeginClose(timeout, callback, state);
            }

            void BaseEndClose(IAsyncResult result)
            {
                base.EndClose(result);
            }

            internal override IAsyncResult BeginClose(TimeSpan timeout, AsyncCallback callback, object state)
            {
                throw new PlatformNotSupportedException("BeginClose to be implemented");
            }

            internal override void EndClose(IAsyncResult result)
            {
                throw new PlatformNotSupportedException("EndClose to be implemented");
            }

            internal override void Close(TimeSpan timeout)
            {
                TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
                base.Close(timeoutHelper.RemainingTime());
                SecurityUtils.CloseTokenProviderIfRequired(this.clientTokenProvider, timeoutHelper.RemainingTime());
            }

            protected override IAsyncResult OnBeginInitiateUpgrade(Stream stream, AsyncCallback callback, object state)
            {
                throw new PlatformNotSupportedException("OnBeginInitiateUpgrade to be implemented");
            }

            protected override Stream OnEndInitiateUpgrade(IAsyncResult result,
                out SecurityMessageProperty remoteSecurity)
            {
                throw new PlatformNotSupportedException("OnEndInitiateUpgrade to be implemented");
            }

            static SecurityMessageProperty CreateServerSecurity(NegotiateStream negotiateStream)
            {
                GenericIdentity remoteIdentity = (GenericIdentity)negotiateStream.RemoteIdentity;
                string principalName = remoteIdentity.Name;
                if ((principalName != null) && (principalName.Length > 0))
                {
                    ReadOnlyCollection<IAuthorizationPolicy> authorizationPolicies = SecurityUtils.CreatePrincipalNameAuthorizationPolicies(principalName);
                    SecurityMessageProperty result = new SecurityMessageProperty();
                    result.TransportToken = new SecurityTokenSpecification(null, authorizationPolicies);
                    result.ServiceSecurityContext = new ServiceSecurityContext(authorizationPolicies);
                    return result;
                }
                else
                {
                    return null;
                }
            }

            protected override Stream OnInitiateUpgrade(Stream stream,
                out SecurityMessageProperty remoteSecurity)
            {
                NegotiateStream negotiateStream;
                string targetName;
                EndpointIdentity identity;

                if (TD.WindowsStreamSecurityOnInitiateUpgradeIsEnabled())
                {
                    TD.WindowsStreamSecurityOnInitiateUpgrade();
                }

                // prepare
                this.InitiateUpgradePrepare(stream, out negotiateStream, out targetName, out identity);

                // authenticate
                try
                {
                    negotiateStream.AuthenticateAsClient(credential, targetName, parent.ProtectionLevel, impersonationLevel);
                }
                catch (AuthenticationException exception)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityNegotiationException(exception.Message,
                        exception));
                }
                catch (IOException ioException)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityNegotiationException(
                        SR.Format(SR.NegotiationFailedIO, ioException.Message), ioException));
                }

                remoteSecurity = CreateServerSecurity(negotiateStream);
                this.ValidateMutualAuth(identity, negotiateStream, remoteSecurity, allowNtlm);

                return negotiateStream;
            }

            void InitiateUpgradePrepare(
                Stream stream,
                out NegotiateStream negotiateStream,
                out string targetName,
                out EndpointIdentity identity)
            {
                negotiateStream = new NegotiateStream(stream);

                targetName = string.Empty;
                identity = null;

                if (parent.IdentityVerifier.TryGetIdentity(this.RemoteAddress, this.Via, out identity))
                {
                    targetName = SecurityUtils.GetSpnFromIdentity(identity, this.RemoteAddress);
                }
                else
                {
                    targetName = SecurityUtils.GetSpnFromTarget(this.RemoteAddress);
                }
            }

            void ValidateMutualAuth(EndpointIdentity expectedIdentity, NegotiateStream negotiateStream,
                SecurityMessageProperty remoteSecurity, bool allowNtlm)
            {
                if (negotiateStream.IsMutuallyAuthenticated)
                {
                    if (expectedIdentity != null)
                    {
                        if (!parent.IdentityVerifier.CheckAccess(expectedIdentity,
                            remoteSecurity.ServiceSecurityContext.AuthorizationContext))
                        {
                            string primaryIdentity = SecurityUtils.GetIdentityNamesFromContext(remoteSecurity.ServiceSecurityContext.AuthorizationContext);
                            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityNegotiationException(SR.Format(
                                SR.RemoteIdentityFailedVerification, primaryIdentity)));
                        }
                    }
                }
                else if (!allowNtlm)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityNegotiationException(SR.Format(
                        SR.StreamMutualAuthNotSatisfied)));
                }
            }
        }
    }
}

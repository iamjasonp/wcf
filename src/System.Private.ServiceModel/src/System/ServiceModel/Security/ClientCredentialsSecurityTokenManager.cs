// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

namespace System.ServiceModel
{
    public class ClientCredentialsSecurityTokenManager : SecurityTokenManager
    {
        private ClientCredentials _parent;

        public ClientCredentialsSecurityTokenManager(ClientCredentials clientCredentials)
        {
            if (clientCredentials == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("clientCredentials");
            }
            _parent = clientCredentials;
        }

        public ClientCredentials ClientCredentials
        {
            get { return _parent; }
        }


        private bool IsDigestAuthenticationScheme(SecurityTokenRequirement requirement)
        {
            if (requirement.Properties.ContainsKey(ServiceModelSecurityTokenRequirement.HttpAuthenticationSchemeProperty))
            {
                AuthenticationSchemes authScheme = (AuthenticationSchemes)requirement.Properties[ServiceModelSecurityTokenRequirement.HttpAuthenticationSchemeProperty];

                if (!authScheme.IsSingleton())
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgument("authScheme", string.Format(SR.HttpRequiresSingleAuthScheme, authScheme));
                }

                return (authScheme == AuthenticationSchemes.Digest);
            }
            else
            {
                return false;
            }
        }


        internal protected bool IsIssuedSecurityTokenRequirement(SecurityTokenRequirement requirement)
        {
            if (requirement != null && requirement.Properties.ContainsKey(ServiceModelSecurityTokenRequirement.IssuerAddressProperty))
            {
                // handle all issued token requirements except for spnego, tlsnego and secure conversation
                if (requirement.TokenType == ServiceModelSecurityTokenTypes.AnonymousSslnego || requirement.TokenType == ServiceModelSecurityTokenTypes.MutualSslnego
                    || requirement.TokenType == ServiceModelSecurityTokenTypes.SecureConversation || requirement.TokenType == ServiceModelSecurityTokenTypes.Spnego)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            return false;
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            if (tokenRequirement == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("tokenRequirement");
            }

            SecurityTokenProvider result = null;
            if (tokenRequirement is RecipientServiceModelSecurityTokenRequirement && tokenRequirement.TokenType == SecurityTokenTypes.X509Certificate && tokenRequirement.KeyUsage == SecurityKeyUsage.Exchange)
            {
                // this is the uncorrelated duplex case
                if (_parent.ClientCertificate.Certificate == null)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(SR.Format(SR.ClientCertificateNotProvidedOnClientCredentials)));
                }
                // TODO: jasonpa 
                throw new PlatformNotSupportedException("Uncorrelated duplex case");
                // result = new X509SecurityTokenProvider(parent.ClientCertificate.Certificate);
            }
            else if (tokenRequirement is InitiatorServiceModelSecurityTokenRequirement)
            {
                InitiatorServiceModelSecurityTokenRequirement initiatorRequirement = tokenRequirement as InitiatorServiceModelSecurityTokenRequirement;
                string tokenType = initiatorRequirement.TokenType;
                if (IsIssuedSecurityTokenRequirement(initiatorRequirement))
                {
                    //FederatedClientCredentialsParameters additionalParameters = this.FindFederatedChannelParameters(tokenRequirement);

                    //if (additionalParameters != null && additionalParameters.IssuedSecurityToken != null)
                    //{
                    //    return new SimpleSecurityTokenProvider(additionalParameters.IssuedSecurityToken, tokenRequirement);
                    //}

                    //result = CreateIssuedSecurityTokenProvider(initiatorRequirement, additionalParameters);

                    // TODO: jasonpa 
                    throw new PlatformNotSupportedException("(IsIssuedSecurityTokenRequirement(initiatorRequirement)");
                }
                else if (tokenType == SecurityTokenTypes.X509Certificate)
                {
                    if (initiatorRequirement.Properties.ContainsKey(SecurityTokenRequirement.KeyUsageProperty) && initiatorRequirement.KeyUsage == SecurityKeyUsage.Exchange)
                    {
                        // result = CreateServerX509TokenProvider(initiatorRequirement.TargetAddress);
                        throw new PlatformNotSupportedException("SecurityKeyUsage.Exchange");

                    }
                    else
                    {
                        if (_parent.ClientCertificate.Certificate == null)
                        {
                            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(SR.Format(SR.ClientCertificateNotProvidedOnClientCredentials)));
                        }
                        result = new X509SecurityTokenProvider(_parent.ClientCertificate.Certificate); 
                    }

                }
                else if (tokenType == SecurityTokenTypes.UserName)
                {
                    //if (parent.UserName.UserName == null)
                    //{
                    //    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(SR.GetString(SR.UserNamePasswordNotProvidedOnClientCredentials)));
                    //}
                    //result = new UserNameSecurityTokenProvider(parent.UserName.UserName, parent.UserName.Password);

                    // TODO: jasonpa 
                    throw new PlatformNotSupportedException("SecurityTokenTypes.UserName");
                }
            }

            if ((result == null) && !tokenRequirement.IsOptionalToken)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new NotSupportedException(SR.Format(SR.SecurityTokenManagerCannotCreateProviderForRequirement, tokenRequirement)));
            }

            return result;
        }


        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            // not referenced anywhere in current code, but must implement abstract. 
            throw ExceptionHelper.PlatformNotSupported("CreateSecurityTokenSerializer(SecurityTokenVersion version) not supported");
        }

        X509SecurityTokenAuthenticator CreateServerX509TokenAuthenticator()
        {
            return new X509SecurityTokenAuthenticator(_parent.ServiceCertificate.Authentication.GetCertificateValidator(), false);
        }

        X509SecurityTokenAuthenticator CreateServerSslX509TokenAuthenticator()
        {
            if (_parent.ServiceCertificate.SslCertificateAuthentication != null)
            {
                return new X509SecurityTokenAuthenticator(_parent.ServiceCertificate.SslCertificateAuthentication.GetCertificateValidator(), false);
            }

            return CreateServerX509TokenAuthenticator();
        }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
        {
                        if (tokenRequirement == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("tokenRequirement");
            }

            outOfBandTokenResolver = null;
            SecurityTokenAuthenticator result = null;

            InitiatorServiceModelSecurityTokenRequirement initiatorRequirement = tokenRequirement as InitiatorServiceModelSecurityTokenRequirement;
            if (initiatorRequirement != null)
            {
                string tokenType = initiatorRequirement.TokenType;
                if (IsIssuedSecurityTokenRequirement(initiatorRequirement))
                {
                    throw ExceptionHelper.PlatformNotSupported("CreateSecurityTokenAuthenticator : GenericXmlSecurityTokenAuthenticator");
                }
                else if (tokenType == SecurityTokenTypes.X509Certificate)
                {
                    if (initiatorRequirement.IsOutOfBandToken)
                    {
                        // when the client side soap security asks for a token authenticator, its for doing
                        // identity checks on the out of band server certificate
                        result = new X509SecurityTokenAuthenticator(X509CertificateValidator.None);
                    }
                    else if (initiatorRequirement.PreferSslCertificateAuthenticator)
                    {
                        result = CreateServerSslX509TokenAuthenticator();
                    }
                    else
                    {
                        result = CreateServerX509TokenAuthenticator();
                    }
                }
                else if (tokenType == SecurityTokenTypes.Rsa)
                {
                    throw ExceptionHelper.PlatformNotSupported("CreateSecurityTokenAuthenticator : SecurityTokenTypes.Rsa");
                }
                else if (tokenType == SecurityTokenTypes.Kerberos)
                {
                    throw ExceptionHelper.PlatformNotSupported("CreateSecurityTokenAuthenticator : SecurityTokenTypes.Kerberos");
                }
                else if (tokenType == ServiceModelSecurityTokenTypes.SecureConversation
                    || tokenType == ServiceModelSecurityTokenTypes.MutualSslnego
                    || tokenType == ServiceModelSecurityTokenTypes.AnonymousSslnego
                    || tokenType == ServiceModelSecurityTokenTypes.Spnego)
                {
                    throw ExceptionHelper.PlatformNotSupported("CreateSecurityTokenAuthenticator : GenericXmlSecurityTokenAuthenticator");
                }
            }
            else if ((tokenRequirement is RecipientServiceModelSecurityTokenRequirement) && tokenRequirement.TokenType == SecurityTokenTypes.X509Certificate)
            {
                // uncorrelated duplex case
                result = CreateServerX509TokenAuthenticator();
            }

            if (result == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new NotSupportedException(SR.Format(SR.SecurityTokenManagerCannotCreateAuthenticatorForRequirement, tokenRequirement)));
            }

            return result;
        }
    }
}

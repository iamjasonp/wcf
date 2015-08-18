// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Security.Cryptography.X509Certificates;
    using ServiceModel;

    public class X509SecurityToken : SecurityToken, IDisposable
    {
        string id;
        X509Certificate2 certificate;
        DateTime effectiveTime = SecurityUtils.MaxUtcDateTime;
        DateTime expirationTime = SecurityUtils.MinUtcDateTime;
        bool disposed = false;
        bool disposable;

        public X509SecurityToken(X509Certificate2 certificate)
            : this(certificate, SecurityUniqueId.Create().Value) 
        { 
        }

        public X509SecurityToken(X509Certificate2 certificate, string id)
            : this(certificate, id, true)
        {
        }

        internal X509SecurityToken(X509Certificate2 certificate, bool clone)
            : this(certificate, SecurityUniqueId.Create().Value, clone)
        {
        }

        internal X509SecurityToken(X509Certificate2 certificate, bool clone, bool disposable)
            : this(certificate, SecurityUniqueId.Create().Value, clone, disposable)
        {
        }

        internal X509SecurityToken(X509Certificate2 certificate, string id, bool clone)
            : this(certificate, id, clone, true)
        {
        }

        internal X509SecurityToken(X509Certificate2 certificate, string id, bool clone, bool disposable)
        {
            if (certificate == null)
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("certificate");
            if (id == null)
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("id");

            this.id = id;

            this.certificate = clone ? new X509Certificate2(certificate.RawData) : certificate;
            // if the cert needs to be cloned then the token owns the clone and should dispose it
            this.disposable = clone || disposable;
        }

        public override string Id
        {
            get { return this.id; }
        }

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get
            {
                // TODO: jasonpa
                throw new PlatformNotSupportedException(); 
                //ThrowIfDisposed();
                //if (this.securityKeys == null)
                //{
                //    List<SecurityKey> temp = new List<SecurityKey>(1);
                //    temp.Add(new X509AsymmetricSecurityKey(this.certificate));
                //    this.securityKeys = temp.AsReadOnly();
                //}
                //return this.securityKeys;
            }
        }

        public override DateTime ValidFrom
        {
            get 
            {
                ThrowIfDisposed();
                if (this.effectiveTime == SecurityUtils.MaxUtcDateTime)
                    this.effectiveTime = this.certificate.NotBefore.ToUniversalTime();
                return this.effectiveTime;
            }
        }

        public override DateTime ValidTo
        {
            get 
            {
                ThrowIfDisposed();
                if (this.expirationTime == SecurityUtils.MinUtcDateTime)
                    this.expirationTime = this.certificate.NotAfter.ToUniversalTime();
                return this.expirationTime;
            }
        }

        public X509Certificate2 Certificate
        {
            get 
            {
                ThrowIfDisposed();
                return this.certificate;
            }
        }
        
        public virtual void Dispose()
        {
            if (this.disposable && !this.disposed)
            {
                this.disposed = true;

                this.certificate.Dispose();
                this.certificate = null; 
            }
        }

        protected void ThrowIfDisposed()
        {
            if (this.disposed)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ObjectDisposedException(this.GetType().FullName));
            }
        }
    }
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.Xml;

namespace System.IdentityModel.Selectors
{
    public abstract class SecurityTokenResolver : ICustomIdentityConfiguration
    {
        /// <summary>
        /// Load custom configuration from Xml
        /// </summary>
        /// <param name="nodelist">Custom configuration elements</param>
        public virtual void LoadCustomConfiguration(XmlNodeList nodelist)
        {
            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(NotImplemented.ByDesignWithMessage(SR.Format(SR.ID0023, this.GetType().AssemblyQualifiedName)));
        }

        public static SecurityTokenResolver CreateDefaultSecurityTokenResolver(ReadOnlyCollection<SecurityToken> tokens, bool canMatchLocalId)
        {
            return new SimpleTokenResolver(tokens, canMatchLocalId);
        }

        private class SimpleTokenResolver : SecurityTokenResolver
        {
            private ReadOnlyCollection<SecurityToken> _tokens;
            private bool _canMatchLocalId;

            public SimpleTokenResolver(ReadOnlyCollection<SecurityToken> tokens, bool canMatchLocalId)
            {
                if (tokens == null)
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("tokens");

                _tokens = tokens;
                _canMatchLocalId = canMatchLocalId;
            }
        }
    }
}

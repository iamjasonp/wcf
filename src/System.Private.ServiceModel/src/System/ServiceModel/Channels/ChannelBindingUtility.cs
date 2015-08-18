// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.ServiceModel.Channels
{
    using System;
    using System.Collections;
    using System.Threading;
    using System.Net;
    using System.Net.Security;
    using System.Runtime;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Authentication.ExtendedProtection;

    static class ChannelBindingUtility
    {
        static ExtendedProtectionPolicy disabledPolicy = new ExtendedProtectionPolicy(PolicyEnforcement.Never);
        static ExtendedProtectionPolicy defaultPolicy = disabledPolicy;

        public static ExtendedProtectionPolicy DisabledPolicy
        {
            get
            {
                return disabledPolicy;
            }
        }

        public static ExtendedProtectionPolicy DefaultPolicy
        {
            get
            {
                return defaultPolicy;
            }
        }

        public static bool IsDefaultPolicy(ExtendedProtectionPolicy policy)
        {
            return Object.ReferenceEquals(policy, defaultPolicy);
        }
        
        public static ChannelBinding GetToken(SslStream stream)
        {
            return GetToken(stream.TransportContext);
        }

        public static ChannelBinding GetToken(TransportContext context)
        {
            ChannelBinding token = null;
            if (context != null)
            {
                token = context.GetChannelBinding(ChannelBindingKind.Endpoint);
            }
            return token;
        }

        public static void TryAddToMessage(ChannelBinding channelBindingToken, Message message, bool messagePropertyOwnsCleanup)
        {
            if (channelBindingToken != null)
            {
                ChannelBindingMessageProperty property = new ChannelBindingMessageProperty(channelBindingToken, messagePropertyOwnsCleanup);
                property.AddTo(message);
                property.Dispose(); //message.Properties.Add() creates a copy...
            }
        }

        //does not validate the ExtendedProtectionPolicy.CustomServiceNames collections on the policies
        public static bool AreEqual(ExtendedProtectionPolicy policy1, ExtendedProtectionPolicy policy2)
        {
            Fx.Assert(policy1 != null, "policy1 param cannot be null");
            Fx.Assert(policy2 != null, "policy2 param cannot be null");

            if (policy1.PolicyEnforcement == PolicyEnforcement.Never && policy2.PolicyEnforcement == PolicyEnforcement.Never)
            {
                return true;
            }

            if (policy1.PolicyEnforcement != policy2.PolicyEnforcement)
            {
                return false;
            }

            if (policy1.ProtectionScenario != policy2.ProtectionScenario)
            {
                return false;
            }

            if (policy1.CustomChannelBinding != policy2.CustomChannelBinding)
            {
                return false;
            }

            return true;
        }

        public static bool IsSubset(ServiceNameCollection primaryList, ServiceNameCollection subset)
        {
            bool result = false;
            if (subset == null || subset.Count == 0)
            {
                result = true;
            }
            else if (primaryList == null || primaryList.Count < subset.Count)
            {
                result = false;
            }
            else
            {
                ServiceNameCollection merged = primaryList.Merge(subset);

                //The merge routine only adds an entry if it is unique.
                result = (merged.Count == primaryList.Count);
            }

            return result;
        }

        public static void Dispose(ref ChannelBinding channelBinding)
        {
            // Explicitly cast to IDisposable to avoid the SecurityException.
            IDisposable disposable = (IDisposable)channelBinding;
            channelBinding = null;
            if (disposable != null)
            {
                disposable.Dispose();
            }
        }
    }
}

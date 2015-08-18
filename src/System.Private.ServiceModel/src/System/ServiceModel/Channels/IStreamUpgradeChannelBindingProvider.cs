// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.ServiceModel.Channels
{
    using System;
    using System.Security.Authentication.ExtendedProtection;

    interface IStreamUpgradeChannelBindingProvider : IChannelBindingProvider
    {
        ChannelBinding GetChannelBinding(StreamUpgradeInitiator upgradeInitiator, ChannelBindingKind kind);
        ChannelBinding GetChannelBinding(StreamUpgradeAcceptor upgradeAcceptor, ChannelBindingKind kind);
    }
}
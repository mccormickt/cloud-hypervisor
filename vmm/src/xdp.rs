// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Move-only resources for one boot attempt. These are not VM configuration.

use std::collections::BTreeMap;

use net_util::PreparedXdpNet;

use crate::vm::Error;
use crate::vm_config::VmConfig;

/// Packet endpoints keyed by `NetConfig::pci_common.id`, a logical NIC ID,
/// not a PCI address. Supply exactly one for each `xdp_external` NIC.
///
/// Keep each endpoint's release fence before transferring this map. The map
/// and its endpoints are consumed on success and on rejection. No resources
/// are saved in `VmConfig`, nor reused for another boot generation.
pub type XdpBootResources = BTreeMap<String, PreparedXdpNet>;

pub(crate) fn validate(config: &mut VmConfig, resources: &XdpBootResources) -> Result<(), Error> {
    config.validate().map_err(Error::ConfigValidation)?;
    let mut expected = 0;
    for net in config.net.iter().flatten().filter(|net| net.xdp_external) {
        let id = net.pci_common.id.as_ref().unwrap();
        let endpoint = resources
            .get(id)
            .ok_or_else(|| Error::AfXdpResource(id.clone()))?;
        if net.xdp_iface.as_deref() != Some(endpoint.iface())
            || net.xdp_zerocopy != endpoint.zerocopy()
        {
            return Err(Error::AfXdpResource(id.clone()));
        }
        expected += 1;
    }
    if expected != resources.len() {
        return Err(Error::AfXdpResource("Unexpected endpoint".to_owned()));
    }
    Ok(())
}

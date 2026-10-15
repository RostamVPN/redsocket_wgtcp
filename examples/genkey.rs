// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let (sk, pk) = redsocket_wgtcp::generate_keypair();
    println!("{sk}\n{pk}");
}

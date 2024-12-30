import * as bip39 from '@scure/bip39';
import { HDKey } from "@scure/bip32";
import { wordlist } from '@scure/bip39/wordlists/english';

export async function generateMnemonic(): Promise<string> {
  return bip39.generateMnemonic(wordlist);
}

export async function mnemonicToHdKey(mnemonic: string) {
  const seed = await bip39.mnemonicToSeed(mnemonic);
  return HDKey.fromMasterSeed(seed);
}

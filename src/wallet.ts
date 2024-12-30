import * as bip39 from '@scure/bip39';
import { ethers } from 'ethers';
import * as ed25519 from '@noble/curves/ed25519';
import bs58 from 'bs58';
import * as ed25519HdKey from 'ed25519-hd-key';
import { mnemonicToHdKey } from './mnemonic';

export enum CoinType {
  Bitcoin = 0,
  Ethereum = 60,
  SOLANA = 501,
}

export interface Wallet {
  address: string;
  privateKey: string;
  mnemonic: string;
  derivePath: string;
}

export async function mnemonicToWallet(mnemonic: string, coinType: CoinType, index: number = 0) : Promise<Wallet> {
  const derivePath = getDerivePath(coinType, index);
  const hdkey = (await mnemonicToHdKey(mnemonic)).derive(derivePath);
  let address;
  if (coinType === CoinType.Ethereum) { // Ethereum
    const wallet = new ethers.Wallet(hdkey.privateKey);
    address = wallet.address;
  } else {
    throw new Error(`Unsupported coin type: ${coinType}`);
  }
  return {
    address,
    privateKey: Buffer.from(hdkey.privateKey).toString('hex'),
    mnemonic,
    derivePath
  };
}

/**
 * Phantom uses a few possible derivation paths, reference: https://stackoverflow.com/questions/76695693/what-standards-does-phantom-wallet-use-for-mnemonic-to-keypair-generation
 * https://help.phantom.com/hc/en-us/articles/12988493966227-What-derivation-paths-does-Phantom-wallet-support
 * https://github.com/abhijayrajvansh/solana-wallet-generator
 * using bip44change
 * m/44'/501'/<NUMBER>'/0'
 * m/44'/501'/<NUMBER>'
 * m/501'/<NUMBER>'/0/0
 * @param mnemonic
 * @returns
 */
export async function mnemonicToSolWallet(mnemonic: string, index: number = 0): Promise<Wallet> {
  const seed = await bip39.mnemonicToSeed(mnemonic);
  const derivePath = `m/44'/501'/${index}'/0'`;
  const seedHex = Buffer.from(seed).toString('hex');
  const { key, chainCode } = ed25519HdKey.derivePath(derivePath, seedHex);
  const privateKey = new Uint8Array(key);
  const publicKey = ed25519.ed25519.getPublicKey(privateKey);
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey);
  secretKey.set(publicKey, 32);
  return {
    address: bs58.encode(publicKey),
    privateKey: bs58.encode(secretKey),
    mnemonic,
    derivePath
  };
}

export function getDerivePath(coinType: CoinType, index: number = 0) {
  return `m/44'/${coinType}'/0'/0/${index}`;
}


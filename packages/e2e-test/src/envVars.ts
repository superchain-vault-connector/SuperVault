import { parseEnv, z } from 'znv'
import { Address as ZodAddress } from 'abitype/zod'
import { deployment } from '@super-vault/contracts'
import { Address } from 'viem'

const zAddressWithDefault = (defaultAddress: Address) =>
  z
    .string()
    .default(defaultAddress)
    .transform((val) => {
      const address = val.trim() !== '' ? val : defaultAddress
      return ZodAddress.parse(address)
    })

export const envVars = parseEnv(import.meta.env, {
  VITE_TOKEN_CONTRACT_ADDRESS: zAddressWithDefault(deployment.deployedAddress),
  VITE_TOKEN_MINTER_ADDRESS: zAddressWithDefault(deployment.ownerAddress),
})

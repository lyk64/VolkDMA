# VolkDMA
A direct memory access library for memory analysis & manipulation, reverse engineering, and debugging.

### Currently supports:
- **DMA session management**
  - RAII DMA handle
  - Optional memory map bootstrapping on construction
  - FPGA prepping routine for stable initialization
  - PID lookup (single and list by name)

- **Process memory & modules**
  - Module metadata (base, size, path), enumeration, and in-memory PE image dumping
  - Typed reads/writes, pointer-chain reads, and string reads
  - Signature scanning in a given VA range with wildcard support
  - RAII move-only scatter handles
  - Preparing and executing scatter reads/writes
  - CR3 fix

- **Input state (kernel-derived)**
  - Cursor position
  - Detecting pressed keys and mouse buttons
  - Built-in VK code to name table

## Included Binaries

To simplify both compilation and usage, this repository includes all required binaries, unmodified from the official MemProcFS and LeechCore releases.

When using this library, place `FTD3XX.dll`, `leechcore.dll`, and `vmm.dll` in the same directory as your executable.
All required DLLs are available in the [`dlls`](dlls) folder.

## Contributors
- **Creator:** [lyk64](https://github.com/lyk64)
- [Stipulations](https://github.com/Stipulations)

## Credits
This project builds upon and utilizes components from [LeechCore](https://github.com/ufrisk/LeechCore) and [MemProcFS](https://github.com/ufrisk/MemProcFS), both created by [Ulf Frisk](https://github.com/ufrisk).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The bundled MemProcFS files are licensed under AGPL-3.0 and the LeechCore files under GPL-3.0.

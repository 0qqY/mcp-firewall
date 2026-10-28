"""Verifies that PyTorch sees the GPU and can run bf16 kernels on it."""

import torch

ok = torch.cuda.is_available()
print("torch", torch.__version__, "| cuda", torch.version.cuda, "| gpu available:", ok)
if ok:
    print(torch.cuda.get_device_name(0), "capability", torch.cuda.get_device_capability(0), "bf16:", torch.cuda.is_bf16_supported())
    x = torch.randn(1024, 1024, device="cuda", dtype=torch.bfloat16)
    print("matmul ok:", (x @ x).float().abs().mean().item() > 0)

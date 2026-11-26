//! NV12 video renderer: two textures (`R8Unorm` luma, `Rg8Unorm` chroma),
//! BT.709 limited-range → RGB in WGSL, drawn aspect-fit (letterboxed) into
//! the frame's main render pass before egui.
//!
//! Frames arrive through the latest-frame-wins [`FrameSlot`](crate::decoder::FrameSlot);
//! [`VideoRenderer::upload`] copies one into the textures (recreated only when
//! the size changes) and [`VideoRenderer::draw`] records the draw. The last
//! uploaded frame stays on screen (e.g. dimmed while the phone screen is off).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use mirror_protocol::geometry::{fit_rect, Rect};

use crate::decoder::{Nv12Frame, UPLOAD_ROW_ALIGN};

/// Staging buffers kept for uploads (one being filled, others in flight).
const STAGING_RING: usize = 3;

/// A reusable upload buffer; `ready` is set once it is mapped for writing
/// again after the GPU consumed it. Reusing these avoids wgpu allocating
/// (and the OS zero-filling) a fresh multi-megabyte staging buffer per
/// frame inside `Queue::write_texture`.
struct Staging {
    buf: wgpu::Buffer,
    ready: Arc<AtomicBool>,
}

const SHADER: &str = r#"
struct Params {
    dim: f32,
    _p0: f32,
    _p1: f32,
    _p2: f32,
};

@group(0) @binding(0) var y_tex: texture_2d<f32>;
@group(0) @binding(1) var uv_tex: texture_2d<f32>;
@group(0) @binding(2) var samp: sampler;
@group(0) @binding(3) var<uniform> params: Params;

struct VsOut {
    @builtin(position) pos: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

// One triangle covering the viewport; uv (0,0) is the top-left texel.
@vertex
fn vs_main(@builtin(vertex_index) i: u32) -> VsOut {
    let x = f32((i << 1u) & 2u);
    let y = f32(i & 2u);
    var out: VsOut;
    out.pos = vec4<f32>(x * 2.0 - 1.0, 1.0 - y * 2.0, 0.0, 1.0);
    out.uv = vec2<f32>(x, y);
    return out;
}

// BT.709, limited ("video") range: Y in [16, 235], Cb/Cr in [16, 240].
@fragment
fn fs_main(in: VsOut) -> @location(0) vec4<f32> {
    let y = (textureSample(y_tex, samp, in.uv).r - 16.0 / 255.0) * (255.0 / 219.0);
    let c = (textureSample(uv_tex, samp, in.uv).rg - vec2<f32>(128.0 / 255.0)) * (255.0 / 224.0);
    let rgb = vec3<f32>(
        y + 1.5748 * c.y,
        y - 0.1873 * c.x - 0.4681 * c.y,
        y + 1.8556 * c.x,
    );
    // The surface is non-sRGB: these gamma-encoded values go out as-is.
    return vec4<f32>(clamp(rgb, vec3<f32>(0.0), vec3<f32>(1.0)) * params.dim, 1.0);
}
"#;

struct Planes {
    y: wgpu::Texture,
    uv: wgpu::Texture,
    bind_group: wgpu::BindGroup,
    width: u32,
    height: u32,
}

pub struct VideoRenderer {
    pipeline: wgpu::RenderPipeline,
    layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    params: wgpu::Buffer,
    dim: f32,
    planes: Option<Planes>,
    staging: Vec<Staging>,
    staging_size: u64,
}

impl VideoRenderer {
    pub fn new(device: &wgpu::Device, target: wgpu::TextureFormat) -> Self {
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("nv12"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let tex_entry = |binding| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture {
                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                view_dimension: wgpu::TextureViewDimension::D2,
                multisampled: false,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("nv12"),
            entries: &[
                tex_entry(0),
                tex_entry(1),
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("nv12"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("nv12"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                compilation_options: Default::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: target,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview_mask: None,
            cache: None,
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("nv12"),
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let params = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("nv12 params"),
            size: 16,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        VideoRenderer {
            pipeline,
            layout,
            sampler,
            params,
            dim: f32::NAN, // never equal: forces the first write
            planes: None,
            staging: Vec::new(),
            staging_size: 0,
        }
    }

    /// Size of the frame on screen, if any.
    pub fn frame_size(&self) -> Option<(u32, u32)> {
        self.planes.as_ref().map(|p| (p.width, p.height))
    }

    /// Forget the current picture (back to home).
    pub fn clear(&mut self) {
        self.planes = None;
    }

    /// Copy `frame` into the textures. Returns false (and keeps the previous
    /// picture) if the frame's planes do not match its declared geometry.
    pub fn upload(
        &mut self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        frame: &Nv12Frame,
    ) -> bool {
        let max = device.limits().max_texture_dimension_2d;
        if !frame.is_consistent() || frame.width > max || frame.height > max {
            return false;
        }
        if self
            .planes
            .as_ref()
            .is_none_or(|p| (p.width, p.height) != (frame.width, frame.height))
        {
            self.planes = Some(self.create_planes(device, frame.width, frame.height));
        }
        if self.upload_staged(device, queue, frame) {
            return true;
        }
        let Some(p) = &self.planes else { return false };
        let write = |tex: &wgpu::Texture, data: &[u8], stride: u32, w: u32, h: u32| {
            queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture: tex,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                data,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(stride),
                    rows_per_image: Some(h),
                },
                wgpu::Extent3d {
                    width: w,
                    height: h,
                    depth_or_array_layers: 1,
                },
            );
        };
        write(&p.y, &frame.y, frame.y_stride, frame.width, frame.height);
        write(
            &p.uv,
            &frame.uv,
            frame.uv_stride,
            frame.uv_width(),
            frame.uv_height(),
        );
        true
    }

    /// Fast path for planes with copy-aligned strides: one memcpy per plane
    /// into a reused mapped buffer, then a GPU buffer→texture copy. Returns
    /// false when not applicable (caller falls back to `write_texture`).
    fn upload_staged(
        &mut self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        frame: &Nv12Frame,
    ) -> bool {
        let align = UPLOAD_ROW_ALIGN as u32;
        if !frame.y_stride.is_multiple_of(align) || !frame.uv_stride.is_multiple_of(align) {
            return false;
        }
        let y_len = frame.y_stride as usize * frame.height as usize;
        let uv_len = frame.uv_stride as usize * frame.uv_height() as usize;
        if frame.y.len() < y_len || frame.uv.len() < uv_len {
            return false;
        }
        let need = (y_len + uv_len) as u64;
        // Run pending map callbacks so finished buffers become ready.
        let _ = device.poll(wgpu::PollType::Poll);
        if self.staging_size < need {
            self.staging.clear();
            self.staging_size = need.next_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT);
        }
        let idx = match self
            .staging
            .iter()
            .position(|s| s.ready.load(Ordering::Acquire))
        {
            Some(i) => i,
            None if self.staging.len() < STAGING_RING => {
                self.staging.push(Staging {
                    buf: device.create_buffer(&wgpu::BufferDescriptor {
                        label: Some("video staging"),
                        size: self.staging_size,
                        usage: wgpu::BufferUsages::MAP_WRITE | wgpu::BufferUsages::COPY_SRC,
                        mapped_at_creation: true,
                    }),
                    ready: Arc::new(AtomicBool::new(true)),
                });
                self.staging.len() - 1
            }
            None => return false, // all in flight: let wgpu stage this one
        };
        let (Some(p), Some(st)) = (&self.planes, self.staging.get(idx)) else {
            return false;
        };
        {
            let Ok(mut view) = st.buf.get_mapped_range_mut(..need) else {
                return false;
            };
            view.slice(..y_len).copy_from_slice(&frame.y[..y_len]);
            view.slice(y_len..).copy_from_slice(&frame.uv[..uv_len]);
        }
        st.buf.unmap();
        st.ready.store(false, Ordering::Release);

        let mut enc = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("video upload"),
        });
        let copy = |enc: &mut wgpu::CommandEncoder, tex, offset, stride, w, h| {
            enc.copy_buffer_to_texture(
                wgpu::TexelCopyBufferInfo {
                    buffer: &st.buf,
                    layout: wgpu::TexelCopyBufferLayout {
                        offset,
                        bytes_per_row: Some(stride),
                        rows_per_image: Some(h),
                    },
                },
                wgpu::TexelCopyTextureInfo {
                    texture: tex,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                wgpu::Extent3d {
                    width: w,
                    height: h,
                    depth_or_array_layers: 1,
                },
            );
        };
        copy(&mut enc, &p.y, 0, frame.y_stride, frame.width, frame.height);
        copy(
            &mut enc,
            &p.uv,
            y_len as u64,
            frame.uv_stride,
            frame.uv_width(),
            frame.uv_height(),
        );
        let ready = st.ready.clone();
        enc.map_buffer_on_submit(&st.buf, wgpu::MapMode::Write, .., move |r| {
            ready.store(r.is_ok(), Ordering::Release);
        });
        queue.submit(std::iter::once(enc.finish()));
        true
    }

    fn create_planes(&self, device: &wgpu::Device, width: u32, height: u32) -> Planes {
        let tex = |label, w, h, format| {
            device.create_texture(&wgpu::TextureDescriptor {
                label: Some(label),
                size: wgpu::Extent3d {
                    width: w,
                    height: h,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            })
        };
        let y = tex("video y", width, height, wgpu::TextureFormat::R8Unorm);
        let uv = tex(
            "video uv",
            width.div_ceil(2),
            height.div_ceil(2),
            wgpu::TextureFormat::Rg8Unorm,
        );
        let yv = y.create_view(&Default::default());
        let uvv = uv.create_view(&Default::default());
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("nv12"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(&yv),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::TextureView(&uvv),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::Sampler(&self.sampler),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: self.params.as_entire_binding(),
                },
            ],
        });
        Planes {
            y,
            uv,
            bind_group,
            width,
            height,
        }
    }

    /// Set the brightness multiplier (1 = normal; lower dims the picture).
    /// Call before the render pass that draws.
    pub fn set_dim(&mut self, queue: &wgpu::Queue, dim: f32) {
        if dim != self.dim {
            self.dim = dim;
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&dim.to_ne_bytes());
            queue.write_buffer(&self.params, 0, &b);
        }
    }

    /// Aspect-fit rectangle (physical pixels) for the current picture in a
    /// `target_w` × `target_h` surface; `None` when there is nothing to draw.
    pub fn fit(&self, target_w: u32, target_h: u32) -> Option<Rect> {
        let (w, h) = self.frame_size()?;
        let r = fit_rect(w, h, f64::from(target_w), f64::from(target_h));
        (r.w >= 1.0 && r.h >= 1.0).then_some(r)
    }

    /// Record the video draw into `pass` (whose target is
    /// `target_w` × `target_h`). Leaves the viewport set to the video rect;
    /// callers drawing afterwards must reset it.
    pub fn draw(&self, pass: &mut wgpu::RenderPass<'_>, target_w: u32, target_h: u32) {
        let (Some(p), Some(r)) = (&self.planes, self.fit(target_w, target_h)) else {
            return;
        };
        pass.set_viewport(r.x as f32, r.y as f32, r.w as f32, r.h as f32, 0.0, 1.0);
        pass.set_pipeline(&self.pipeline);
        pass.set_bind_group(0, &p.bind_group, &[]);
        pass.draw(0..3, 0..1);
    }
}

#[cfg(test)]
mod tests {
    /// Reference conversion matching the shader, for checking constants.
    fn bt709_limited(y: u8, cb: u8, cr: u8) -> [f32; 3] {
        let y = (y as f32 / 255.0 - 16.0 / 255.0) * (255.0 / 219.0);
        let cb = (cb as f32 / 255.0 - 128.0 / 255.0) * (255.0 / 224.0);
        let cr = (cr as f32 / 255.0 - 128.0 / 255.0) * (255.0 / 224.0);
        [
            (y + 1.5748 * cr).clamp(0.0, 1.0),
            (y - 0.1873 * cb - 0.4681 * cr).clamp(0.0, 1.0),
            (y + 1.8556 * cb).clamp(0.0, 1.0),
        ]
    }

    fn close(a: [f32; 3], b: [f32; 3]) -> bool {
        a.iter().zip(b).all(|(x, y)| (x - y).abs() < 0.01)
    }

    #[test]
    fn limited_range_black_white_and_primaries() {
        assert!(close(bt709_limited(16, 128, 128), [0.0, 0.0, 0.0]));
        assert!(close(bt709_limited(235, 128, 128), [1.0, 1.0, 1.0]));
        // BT.709 limited-range 100% colour bars.
        assert!(close(bt709_limited(63, 102, 240), [1.0, 0.0, 0.0]), "red");
        assert!(close(bt709_limited(173, 42, 26), [0.0, 1.0, 0.0]), "green");
        assert!(close(bt709_limited(32, 240, 118), [0.0, 0.0, 1.0]), "blue");
    }

    #[test]
    fn shader_constants_match_reference() {
        let s = super::SHADER;
        for c in [
            "1.5748",
            "0.1873",
            "0.4681",
            "1.8556",
            "16.0 / 255.0",
            "255.0 / 219.0",
            "255.0 / 224.0",
        ] {
            assert!(s.contains(c), "shader lacks {c}");
        }
    }
}

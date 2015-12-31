// Copyright 2015 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <unordered_map>

#include "common/common_types.h"
#include "common/hash.h"

#include "video_core/pica.h"
#include "video_core/rasterizer_interface.h"
#include "video_core/renderer_opengl/gl_rasterizer_cache.h"
#include "video_core/renderer_opengl/gl_state.h"
#include "video_core/shader/shader_interpreter.h"

/**
 * This struct contains all state used to generate the GLSL shader program that emulates the current
 * Pica register configuration. This struct is used as a cache key for generated GLSL shader
 * programs. The functions in gl_shader_gen.cpp should retrieve state from this struct only, not by
 * directly accessing Pica registers. This should reduce the risk of bugs in shader generation where
 * Pica state is not being captured in the shader cache key, thereby resulting in (what should be)
 * two separate shaders sharing the same key.
 */
struct PicaShaderConfig {
    /// Construct a PicaShaderConfig with the current Pica register configuration.
    static PicaShaderConfig CurrentConfig() {
        PicaShaderConfig res;
        const auto& regs = Pica::g_state.regs;

        res.alpha_test_func = regs.output_merger.alpha_test.enable ?
            regs.output_merger.alpha_test.func.Value() : Pica::Regs::CompareFunc::Always;

        // Copy relevant TevStageConfig fields only. We're doing this manually (instead of calling
        // the GetTevStages() function) because BitField explicitly disables copies.

        res.tev_stages[0].sources_raw = regs.tev_stage0.sources_raw;
        res.tev_stages[1].sources_raw = regs.tev_stage1.sources_raw;
        res.tev_stages[2].sources_raw = regs.tev_stage2.sources_raw;
        res.tev_stages[3].sources_raw = regs.tev_stage3.sources_raw;
        res.tev_stages[4].sources_raw = regs.tev_stage4.sources_raw;
        res.tev_stages[5].sources_raw = regs.tev_stage5.sources_raw;

        res.tev_stages[0].modifiers_raw = regs.tev_stage0.modifiers_raw;
        res.tev_stages[1].modifiers_raw = regs.tev_stage1.modifiers_raw;
        res.tev_stages[2].modifiers_raw = regs.tev_stage2.modifiers_raw;
        res.tev_stages[3].modifiers_raw = regs.tev_stage3.modifiers_raw;
        res.tev_stages[4].modifiers_raw = regs.tev_stage4.modifiers_raw;
        res.tev_stages[5].modifiers_raw = regs.tev_stage5.modifiers_raw;

        res.tev_stages[0].ops_raw = regs.tev_stage0.ops_raw;
        res.tev_stages[1].ops_raw = regs.tev_stage1.ops_raw;
        res.tev_stages[2].ops_raw = regs.tev_stage2.ops_raw;
        res.tev_stages[3].ops_raw = regs.tev_stage3.ops_raw;
        res.tev_stages[4].ops_raw = regs.tev_stage4.ops_raw;
        res.tev_stages[5].ops_raw = regs.tev_stage5.ops_raw;

        res.tev_stages[0].scales_raw = regs.tev_stage0.scales_raw;
        res.tev_stages[1].scales_raw = regs.tev_stage1.scales_raw;
        res.tev_stages[2].scales_raw = regs.tev_stage2.scales_raw;
        res.tev_stages[3].scales_raw = regs.tev_stage3.scales_raw;
        res.tev_stages[4].scales_raw = regs.tev_stage4.scales_raw;
        res.tev_stages[5].scales_raw = regs.tev_stage5.scales_raw;

        res.combiner_buffer_input =
            regs.tev_combiner_buffer_input.update_mask_rgb.Value() |
            regs.tev_combiner_buffer_input.update_mask_a.Value() << 4;

        // Fragment lighting

        res.lighting.enable = !regs.lighting.disable;
        res.lighting.src_num = regs.lighting.src_num + 1;

        for (unsigned light_index = 0; light_index < res.lighting.src_num; ++light_index) {
            unsigned num = regs.lighting.light_enable.GetNum(light_index);
            const auto& light = regs.lighting.light[num];
            res.lighting.light[light_index].num = num;
            res.lighting.light[light_index].directional = light.directional != 0;
            res.lighting.light[light_index].two_sided_diffuse = light.two_sided_diffuse != 0;
            res.lighting.light[light_index].dist_atten_enable = regs.lighting.IsDistAttenEnabled(num);
            res.lighting.light[light_index].dist_atten_bias = Pica::float20::FromRaw(light.dist_atten_bias).ToFloat32();
            res.lighting.light[light_index].dist_atten_scale = Pica::float20::FromRaw(light.dist_atten_scale).ToFloat32();
        }

        res.lighting.lut_d0.enable = regs.lighting.lut_enable_d0 == 0;
        res.lighting.lut_d0.abs_input = regs.lighting.abs_lut_input.d0 == 0;
        res.lighting.lut_d0.type = regs.lighting.lut_input.d0.Value();
        res.lighting.lut_d0.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.d0);

        res.lighting.lut_d1.enable = regs.lighting.lut_enable_d1 == 0;
        res.lighting.lut_d1.abs_input = regs.lighting.abs_lut_input.d1 == 0;
        res.lighting.lut_d1.type = regs.lighting.lut_input.d1.Value();
        res.lighting.lut_d1.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.d1);

        res.lighting.lut_fr.enable = regs.lighting.lut_enable_fr == 0;
        res.lighting.lut_fr.abs_input = regs.lighting.abs_lut_input.fr == 0;
        res.lighting.lut_fr.type = regs.lighting.lut_input.fr.Value();
        res.lighting.lut_fr.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.fr);

        res.lighting.lut_rr.enable = regs.lighting.lut_enable_rr == 0;
        res.lighting.lut_rr.abs_input = regs.lighting.abs_lut_input.rr == 0;
        res.lighting.lut_rr.type = regs.lighting.lut_input.rr.Value();
        res.lighting.lut_rr.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.rr);

        res.lighting.lut_rg.enable = regs.lighting.lut_enable_rg == 0;
        res.lighting.lut_rg.abs_input = regs.lighting.abs_lut_input.rg == 0;
        res.lighting.lut_rg.type = regs.lighting.lut_input.rg.Value();
        res.lighting.lut_rg.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.rg);

        res.lighting.lut_rb.enable = regs.lighting.lut_enable_rb == 0;
        res.lighting.lut_rb.abs_input = regs.lighting.abs_lut_input.rb == 0;
        res.lighting.lut_rb.type = regs.lighting.lut_input.rb.Value();
        res.lighting.lut_rb.scale = regs.lighting.lut_scale.GetScale(regs.lighting.lut_scale.rb);

        res.lighting.config = regs.lighting.config;
        res.lighting.fresnel_selector = regs.lighting.fresnel_selector;
        res.lighting.bump_mode = regs.lighting.bump_mode;
        res.lighting.bump_selector = regs.lighting.bump_selector;
        res.lighting.bump_renorm = regs.lighting.bump_renorm == 0;
        res.lighting.clamp_highlights = regs.lighting.clamp_highlights != 0;

        return res;
    }

    bool TevStageUpdatesCombinerBufferColor(unsigned stage_index) const {
        return (stage_index < 4) && (combiner_buffer_input & (1 << stage_index));
    }

    bool TevStageUpdatesCombinerBufferAlpha(unsigned stage_index) const {
        return (stage_index < 4) && ((combiner_buffer_input >> 4) & (1 << stage_index));
    }

    bool operator ==(const PicaShaderConfig& o) const {
        return std::memcmp(this, &o, sizeof(PicaShaderConfig)) == 0;
    };

    Pica::Regs::CompareFunc alpha_test_func = Pica::Regs::CompareFunc::Never;
    std::array<Pica::Regs::TevStageConfig, 6> tev_stages = {};
    u8 combiner_buffer_input = 0;

    struct {
        struct {
            unsigned num = 0;
            bool directional = false;
            bool two_sided_diffuse = false;
            bool dist_atten_enable = false;
            GLfloat dist_atten_scale = 0.0f;
            GLfloat dist_atten_bias = 0.0f;
        } light[8];

        bool enable = false;
        unsigned src_num = 0;
        Pica::Regs::LightingBumpMode bump_mode = Pica::Regs::LightingBumpMode::None;
        unsigned bump_selector = 0;
        bool bump_renorm = false;
        bool clamp_highlights = false;

        Pica::Regs::LightingConfig config = Pica::Regs::LightingConfig::Config0;
        Pica::Regs::LightingFresnelSelector fresnel_selector = Pica::Regs::LightingFresnelSelector::None;

        struct {
            bool enable = false;
            bool abs_input = false;
            Pica::Regs::LightingLutInput type = Pica::Regs::LightingLutInput::NH;
            float scale = 1.0f;
        } lut_d0, lut_d1, lut_fr, lut_rr, lut_rg, lut_rb;
    } lighting;
};

namespace std {

template <>
struct hash<PicaShaderConfig> {
    size_t operator()(const PicaShaderConfig& k) const {
        return Common::ComputeHash64(&k, sizeof(PicaShaderConfig));
    }
};

} // namespace std

class RasterizerOpenGL : public VideoCore::RasterizerInterface {
public:

    RasterizerOpenGL();
    ~RasterizerOpenGL() override;

    void InitObjects() override;
    void Reset() override;
    void AddTriangle(const Pica::Shader::OutputVertex& v0,
                     const Pica::Shader::OutputVertex& v1,
                     const Pica::Shader::OutputVertex& v2) override;
    void DrawTriangles() override;
    void FlushFramebuffer() override;
    void NotifyPicaRegisterChanged(u32 id) override;
    void FlushRegion(PAddr addr, u32 size) override;
    void InvalidateRegion(PAddr addr, u32 size) override;

    /// OpenGL shader generated for a given Pica register state
    struct PicaShader {
        /// OpenGL shader resource
        OGLShader shader;
    };

private:

    /// Structure used for storing information about color textures
    struct TextureInfo {
        OGLTexture texture;
        GLsizei width;
        GLsizei height;
        Pica::Regs::ColorFormat format;
        GLenum gl_format;
        GLenum gl_type;
    };

    /// Structure used for storing information about depth textures
    struct DepthTextureInfo {
        OGLTexture texture;
        GLsizei width;
        GLsizei height;
        Pica::Regs::DepthFormat format;
        GLenum gl_format;
        GLenum gl_type;
    };

    struct SamplerInfo {
        using TextureConfig = Pica::Regs::TextureConfig;

        OGLSampler sampler;

        /// Creates the sampler object, initializing its state so that it's in sync with the SamplerInfo struct.
        void Create();
        /// Syncs the sampler object with the config, updating any necessary state.
        void SyncWithConfig(const TextureConfig& config);

    private:
        TextureConfig::TextureFilter mag_filter;
        TextureConfig::TextureFilter min_filter;
        TextureConfig::WrapMode wrap_s;
        TextureConfig::WrapMode wrap_t;
        u32 border_color;
    };

    /// Structure that the hardware rendered vertices are composed of
    struct HardwareVertex {
        HardwareVertex(const Pica::Shader::OutputVertex& v) {
            position[0] = v.pos.x.ToFloat32();
            position[1] = v.pos.y.ToFloat32();
            position[2] = v.pos.z.ToFloat32();
            position[3] = v.pos.w.ToFloat32();
            color[0] = v.color.x.ToFloat32();
            color[1] = v.color.y.ToFloat32();
            color[2] = v.color.z.ToFloat32();
            color[3] = v.color.w.ToFloat32();
            tex_coord0[0] = v.tc0.x.ToFloat32();
            tex_coord0[1] = v.tc0.y.ToFloat32();
            tex_coord1[0] = v.tc1.x.ToFloat32();
            tex_coord1[1] = v.tc1.y.ToFloat32();
            tex_coord2[0] = v.tc2.x.ToFloat32();
            tex_coord2[1] = v.tc2.y.ToFloat32();
            normquat[0] = v.quat.x.ToFloat32();
            normquat[1] = v.quat.y.ToFloat32();
            normquat[2] = v.quat.z.ToFloat32();
            normquat[3] = v.quat.w.ToFloat32();
            view[0] = v.view.x.ToFloat32();
            view[1] = v.view.y.ToFloat32();
            view[2] = v.view.z.ToFloat32();
        }

        GLfloat position[4];
        GLfloat color[4];
        GLfloat tex_coord0[2];
        GLfloat tex_coord1[2];
        GLfloat tex_coord2[2];
        GLfloat normquat[4];
        GLfloat view[3];
    };

    struct LightSrc {
        std::array<GLfloat, 3> specular_0;
        INSERT_PADDING_WORDS(1);
        std::array<GLfloat, 3> specular_1;
        INSERT_PADDING_WORDS(1);
        std::array<GLfloat, 3> diffuse;
        INSERT_PADDING_WORDS(1);
        std::array<GLfloat, 3> ambient;
        INSERT_PADDING_WORDS(1);
        std::array<GLfloat, 3> position;
        INSERT_PADDING_WORDS(1);
    };

    /// Uniform structure for the Uniform Buffer Object, all members must be 16-byte aligned
    struct UniformData {
        // A vec4 color for each of the six tev stages
        std::array<GLfloat, 4> const_color[6];
        std::array<GLfloat, 4> tev_combiner_buffer_color;
        GLint alphatest_ref;
        INSERT_PADDING_WORDS(3);
        std::array<GLfloat, 3> lighting_global_ambient;
        INSERT_PADDING_WORDS(1);
        LightSrc light_src[8];
    };

    static_assert(sizeof(UniformData) == 0x310, "The size of the UniformData structure has changed, update the structure in the shader");
    static_assert(sizeof(UniformData) < 16384, "UniformData structure must be less than 16kb as per the OpenGL spec");

    /// Reconfigure the OpenGL color texture to use the given format and dimensions
    void ReconfigureColorTexture(TextureInfo& texture, Pica::Regs::ColorFormat format, u32 width, u32 height);

    /// Reconfigure the OpenGL depth texture to use the given format and dimensions
    void ReconfigureDepthTexture(DepthTextureInfo& texture, Pica::Regs::DepthFormat format, u32 width, u32 height);

    /// Sets the OpenGL shader in accordance with the current PICA register state
    void SetShader();

    /// Syncs the state and contents of the OpenGL framebuffer to match the current PICA framebuffer
    void SyncFramebuffer();

    /// Syncs the cull mode to match the PICA register
    void SyncCullMode();

    /// Syncs the blend enabled status to match the PICA register
    void SyncBlendEnabled();

    /// Syncs the blend functions to match the PICA register
    void SyncBlendFuncs();

    /// Syncs the blend color to match the PICA register
    void SyncBlendColor();

    /// Syncs the alpha test states to match the PICA register
    void SyncAlphaTest();

    /// Syncs the logic op states to match the PICA register
    void SyncLogicOp();

    /// Syncs the stencil test states to match the PICA register
    void SyncStencilTest();

    /// Syncs the depth test states to match the PICA register
    void SyncDepthTest();

    /// Syncs the TEV constant color to match the PICA register
    void SyncTevConstColor(int tev_index, const Pica::Regs::TevStageConfig& tev_stage);

    /// Syncs the TEV combiner color buffer to match the PICA register
    void SyncCombinerColor();

    /// Syncs the lighting global ambient color to match the PICA register
    void SyncGlobalAmbient();

    /// Syncs the lighting lookup tables
    void SyncLightingLUT(unsigned index);

    /// Syncs the specified light's diffuse color to match the PICA register
    void SyncLightDiffuse(int light_index);

    /// Syncs the specified light's ambient color to match the PICA register
    void SyncLightAmbient(int light_index);

    /// Syncs the specified light's position to match the PICA register
    void SyncLightPosition(int light_index);

    /// Syncs the specified light's specular 0 color to match the PICA register
    void SyncLightSpecular0(int light_index);

    /// Syncs the specified light's specular 1 color to match the PICA register
    void SyncLightSpecular1(int light_index);

    /// Syncs the remaining OpenGL drawing state to match the current PICA state
    void SyncDrawState();

    /// Copies the 3DS color framebuffer into the OpenGL color framebuffer texture
    void ReloadColorBuffer();

    /// Copies the 3DS depth framebuffer into the OpenGL depth framebuffer texture
    void ReloadDepthBuffer();

    /**
     * Save the current OpenGL color framebuffer to the current PICA framebuffer in 3DS memory
     * Loads the OpenGL framebuffer textures into temporary buffers
     * Then copies into the 3DS framebuffer using proper Morton order
     */
    void CommitColorBuffer();

    /**
     * Save the current OpenGL depth framebuffer to the current PICA framebuffer in 3DS memory
     * Loads the OpenGL framebuffer textures into temporary buffers
     * Then copies into the 3DS framebuffer using proper Morton order
     */
    void CommitDepthBuffer();

    RasterizerCacheOpenGL res_cache;

    std::vector<HardwareVertex> vertex_batch;

    OpenGLState state;

    PAddr last_fb_color_addr;
    PAddr last_fb_depth_addr;

    // Hardware rasterizer
    std::array<SamplerInfo, 3> texture_samplers;
    TextureInfo fb_color_texture;
    DepthTextureInfo fb_depth_texture;

    std::unordered_map<PicaShaderConfig, std::unique_ptr<PicaShader>> shader_cache;
    const PicaShader* current_shader = nullptr;

    struct {
        UniformData data;
        bool lut_dirty[6];
        bool dirty;
    } uniform_block_data;

    OGLVertexArray vertex_array;
    OGLBuffer vertex_buffer;
    OGLBuffer uniform_buffer;
    OGLFramebuffer framebuffer;

    std::array<OGLTexture, 6> lighting_lut;
    std::array<std::array<std::array<GLfloat, 4>, 256>, 6> lighting_lut_data;
};

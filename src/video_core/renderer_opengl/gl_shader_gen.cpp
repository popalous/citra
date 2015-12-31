// Copyright 2015 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "video_core/pica.h"
#include "video_core/renderer_opengl/gl_rasterizer.h"
#include "video_core/renderer_opengl/gl_shader_gen.h"

using Pica::Regs;
using TevStageConfig = Regs::TevStageConfig;

namespace GLShader {

/// Detects if a TEV stage is configured to be skipped (to avoid generating unnecessary code)
static bool IsPassThroughTevStage(const TevStageConfig& stage) {
    return (stage.color_op             == TevStageConfig::Operation::Replace &&
            stage.alpha_op             == TevStageConfig::Operation::Replace &&
            stage.color_source1        == TevStageConfig::Source::Previous &&
            stage.alpha_source1        == TevStageConfig::Source::Previous &&
            stage.color_modifier1      == TevStageConfig::ColorModifier::SourceColor &&
            stage.alpha_modifier1      == TevStageConfig::AlphaModifier::SourceAlpha &&
            stage.GetColorMultiplier() == 1 &&
            stage.GetAlphaMultiplier() == 1);
}

/// Writes the specified TEV stage source component(s)
static void AppendSource(std::string& out, TevStageConfig::Source source,
        const std::string& index_name) {
    using Source = TevStageConfig::Source;
    switch (source) {
    case Source::PrimaryColor:
        out += "primary_color";
        break;
    case Source::PrimaryFragmentColor:
        out += "primary_fragment_color";
        break;
    case Source::SecondaryFragmentColor:
        out += "secondary_fragment_color";
        break;
    case Source::Texture0:
        out += "texture(tex[0], texcoord[0])";
        break;
    case Source::Texture1:
        out += "texture(tex[1], texcoord[1])";
        break;
    case Source::Texture2:
        out += "texture(tex[2], texcoord[2])";
        break;
    case Source::PreviousBuffer:
        out += "combiner_buffer";
        break;
    case Source::Constant:
        ((out += "const_color[") += index_name) += ']';
        break;
    case Source::Previous:
        out += "last_tex_env_out";
        break;
    default:
        out += "vec4(0.0)";
        LOG_CRITICAL(Render_OpenGL, "Unknown source op %u", source);
        break;
    }
}

/// Writes the color components to use for the specified TEV stage color modifier
static void AppendColorModifier(std::string& out, TevStageConfig::ColorModifier modifier,
        TevStageConfig::Source source, const std::string& index_name) {
    using ColorModifier = TevStageConfig::ColorModifier;
    switch (modifier) {
    case ColorModifier::SourceColor:
        AppendSource(out, source, index_name);
        out += ".rgb";
        break;
    case ColorModifier::OneMinusSourceColor:
        out += "vec3(1.0) - ";
        AppendSource(out, source, index_name);
        out += ".rgb";
        break;
    case ColorModifier::SourceAlpha:
        AppendSource(out, source, index_name);
        out += ".aaa";
        break;
    case ColorModifier::OneMinusSourceAlpha:
        out += "vec3(1.0) - ";
        AppendSource(out, source, index_name);
        out += ".aaa";
        break;
    case ColorModifier::SourceRed:
        AppendSource(out, source, index_name);
        out += ".rrr";
        break;
    case ColorModifier::OneMinusSourceRed:
        out += "vec3(1.0) - ";
        AppendSource(out, source, index_name);
        out += ".rrr";
        break;
    case ColorModifier::SourceGreen:
        AppendSource(out, source, index_name);
        out += ".ggg";
        break;
    case ColorModifier::OneMinusSourceGreen:
        out += "vec3(1.0) - ";
        AppendSource(out, source, index_name);
        out += ".ggg";
        break;
    case ColorModifier::SourceBlue:
        AppendSource(out, source, index_name);
        out += ".bbb";
        break;
    case ColorModifier::OneMinusSourceBlue:
        out += "vec3(1.0) - ";
        AppendSource(out, source, index_name);
        out += ".bbb";
        break;
    default:
        out += "vec3(0.0)";
        LOG_CRITICAL(Render_OpenGL, "Unknown color modifier op %u", modifier);
        break;
    }
}

/// Writes the alpha component to use for the specified TEV stage alpha modifier
static void AppendAlphaModifier(std::string& out, TevStageConfig::AlphaModifier modifier,
        TevStageConfig::Source source, const std::string& index_name) {
    using AlphaModifier = TevStageConfig::AlphaModifier;
    switch (modifier) {
    case AlphaModifier::SourceAlpha:
        AppendSource(out, source, index_name);
        out += ".a";
        break;
    case AlphaModifier::OneMinusSourceAlpha:
        out += "1.0 - ";
        AppendSource(out, source, index_name);
        out += ".a";
        break;
    case AlphaModifier::SourceRed:
        AppendSource(out, source, index_name);
        out += ".r";
        break;
    case AlphaModifier::OneMinusSourceRed:
        out += "1.0 - ";
        AppendSource(out, source, index_name);
        out += ".r";
        break;
    case AlphaModifier::SourceGreen:
        AppendSource(out, source, index_name);
        out += ".g";
        break;
    case AlphaModifier::OneMinusSourceGreen:
        out += "1.0 - ";
        AppendSource(out, source, index_name);
        out += ".g";
        break;
    case AlphaModifier::SourceBlue:
        AppendSource(out, source, index_name);
        out += ".b";
        break;
    case AlphaModifier::OneMinusSourceBlue:
        out += "1.0 - ";
        AppendSource(out, source, index_name);
        out += ".b";
        break;
    default:
        out += "0.0";
        LOG_CRITICAL(Render_OpenGL, "Unknown alpha modifier op %u", modifier);
        break;
    }
}

/// Writes the combiner function for the color components for the specified TEV stage operation
static void AppendColorCombiner(std::string& out, TevStageConfig::Operation operation,
        const std::string& variable_name) {
    out += "clamp(";
    using Operation = TevStageConfig::Operation;
    switch (operation) {
    case Operation::Replace:
        out += variable_name + "[0]";
        break;
    case Operation::Modulate:
        out += variable_name + "[0] * " + variable_name + "[1]";
        break;
    case Operation::Add:
        out += variable_name + "[0] + " + variable_name + "[1]";
        break;
    case Operation::AddSigned:
        out += variable_name + "[0] + " + variable_name + "[1] - vec3(0.5)";
        break;
    case Operation::Lerp:
        // TODO(bunnei): Verify if HW actually does this per-component, otherwise we can just use builtin lerp
        out += variable_name + "[0] * " + variable_name + "[2] + " + variable_name + "[1] * (vec3(1.0) - " + variable_name + "[2])";
        break;
    case Operation::Subtract:
        out += variable_name + "[0] - " + variable_name + "[1]";
        break;
    case Operation::MultiplyThenAdd:
        out += variable_name + "[0] * " + variable_name + "[1] + " + variable_name + "[2]";
        break;
    case Operation::AddThenMultiply:
        out += "min(" + variable_name + "[0] + " + variable_name + "[1], vec3(1.0)) * " + variable_name + "[2]";
        break;
    default:
        out += "vec3(0.0)";
        LOG_CRITICAL(Render_OpenGL, "Unknown color combiner operation: %u", operation);
        break;
    }
    out += ", vec3(0.0), vec3(1.0))"; // Clamp result to 0.0, 1.0
}

/// Writes the combiner function for the alpha component for the specified TEV stage operation
static void AppendAlphaCombiner(std::string& out, TevStageConfig::Operation operation,
        const std::string& variable_name) {
    out += "clamp(";
    using Operation = TevStageConfig::Operation;
    switch (operation) {
    case Operation::Replace:
        out += variable_name + "[0]";
        break;
    case Operation::Modulate:
        out += variable_name + "[0] * " + variable_name + "[1]";
        break;
    case Operation::Add:
        out += variable_name + "[0] + " + variable_name + "[1]";
        break;
    case Operation::AddSigned:
        out += variable_name + "[0] + " + variable_name + "[1] - 0.5";
        break;
    case Operation::Lerp:
        out += variable_name + "[0] * " + variable_name + "[2] + " + variable_name + "[1] * (1.0 - " + variable_name + "[2])";
        break;
    case Operation::Subtract:
        out += variable_name + "[0] - " + variable_name + "[1]";
        break;
    case Operation::MultiplyThenAdd:
        out += variable_name + "[0] * " + variable_name + "[1] + " + variable_name + "[2]";
        break;
    case Operation::AddThenMultiply:
        out += "min(" + variable_name + "[0] + " + variable_name + "[1], 1.0) * " + variable_name + "[2]";
        break;
    default:
        out += "0.0";
        LOG_CRITICAL(Render_OpenGL, "Unknown alpha combiner operation: %u", operation);
        break;
    }
    out += ", 0.0, 1.0)";
}

/// Writes the if-statement condition used to evaluate alpha testing
static void AppendAlphaTestCondition(std::string& out, Regs::CompareFunc func) {
    using CompareFunc = Regs::CompareFunc;
    switch (func) {
    case CompareFunc::Never:
        out += "true";
        break;
    case CompareFunc::Always:
        out += "false";
        break;
    case CompareFunc::Equal:
    case CompareFunc::NotEqual:
    case CompareFunc::LessThan:
    case CompareFunc::LessThanOrEqual:
    case CompareFunc::GreaterThan:
    case CompareFunc::GreaterThanOrEqual:
    {
        static const char* op[] = { "!=", "==", ">=", ">", "<=", "<", };
        unsigned index = (unsigned)func - (unsigned)CompareFunc::Equal;
        out += "int(last_tex_env_out.a * 255.0f) " + std::string(op[index]) + " alphatest_ref";
        break;
    }

    default:
        out += "false";
        LOG_CRITICAL(Render_OpenGL, "Unknown alpha test condition %u", func);
        break;
    }
}

/// Writes the code to emulate the specified TEV stage
static void WriteTevStage(std::string& out, const PicaShaderConfig& config, unsigned index) {
    auto& stage = config.tev_stages[index];
    if (!IsPassThroughTevStage(stage)) {
        std::string index_name = std::to_string(index);

        out += "vec3 color_results_" + index_name + "[3] = vec3[3](";
        AppendColorModifier(out, stage.color_modifier1, stage.color_source1, index_name);
        out += ", ";
        AppendColorModifier(out, stage.color_modifier2, stage.color_source2, index_name);
        out += ", ";
        AppendColorModifier(out, stage.color_modifier3, stage.color_source3, index_name);
        out += ");\n";

        out += "vec3 color_output_" + index_name + " = ";
        AppendColorCombiner(out, stage.color_op, "color_results_" + index_name);
        out += ";\n";

        out += "float alpha_results_" + index_name + "[3] = float[3](";
        AppendAlphaModifier(out, stage.alpha_modifier1, stage.alpha_source1, index_name);
        out += ", ";
        AppendAlphaModifier(out, stage.alpha_modifier2, stage.alpha_source2, index_name);
        out += ", ";
        AppendAlphaModifier(out, stage.alpha_modifier3, stage.alpha_source3, index_name);
        out += ");\n";

        out += "float alpha_output_" + index_name + " = ";
        AppendAlphaCombiner(out, stage.alpha_op, "alpha_results_" + index_name);
        out += ";\n";

        out += "last_tex_env_out = vec4("
            "clamp(color_output_" + index_name + " * " + std::to_string(stage.GetColorMultiplier()) + ".0, vec3(0.0), vec3(1.0)),"
            "clamp(alpha_output_" + index_name + " * " + std::to_string(stage.GetAlphaMultiplier()) + ".0, 0.0, 1.0));\n";
    }

    out += "combiner_buffer = next_combiner_buffer;\n";

    if (config.TevStageUpdatesCombinerBufferColor(index))
        out += "next_combiner_buffer.rgb = last_tex_env_out.rgb;\n";

    if (config.TevStageUpdatesCombinerBufferAlpha(index))
        out += "next_combiner_buffer.a = last_tex_env_out.a;\n";
}

/// Writes the code to emulate fragment lighting
static void WriteLighting(std::string& out, const PicaShaderConfig& config) {
    // Define lighting globals
    out += "vec4 diffuse_sum = vec4(0.0, 0.0, 0.0, 1.0);\n";
    out += "vec4 specular_sum = vec4(0.0, 0.0, 0.0, 1.0);\n";
    out += "vec3 light_vector = vec3(0.0);\n";
    out += "vec3 refl_value = vec3(0.0);\n";

    // Compute fragment normals
    if (config.lighting.bump_mode == Pica::Regs::LightingBumpMode::NormalMap) {
        // Bump mapping is enabled using a normal map, read perturbation vector from the selected texture
        std::string bump_selector = std::to_string(config.lighting.bump_selector);
        out += "vec3 surface_normal = 2.0 * texture(tex[" + bump_selector + "], texcoord[" + bump_selector + "]).rgb - 1.0;\n";

        // Recompute Z-component of perturbation if 'renorm' is enabled, this provides a higher precision result
        if (config.lighting.bump_renorm) {
            std::string val = "1.0 - (surface_normal.x*surface_normal.x + surface_normal.y*surface_normal.y)";
            out += "surface_normal.z = (" + val + ") > 0 ? sqrt(" + val + ") : 0;\n";
        }
    } else if (config.lighting.bump_mode == Pica::Regs::LightingBumpMode::TangentMap) {
        // Bump mapping is enabled using a tangent map
        LOG_CRITICAL(HW_GPU, "unimplemented bump mapping mode (tangent mapping)");
        UNIMPLEMENTED();
    } else {
        // No bump mapping - surface local normal is just a unit normal
        out += "vec3 surface_normal = vec3(0.0, 0.0, 1.0);\n";
    }

    // Rotate the surface-local normal by the interpolated normal quaternion to convert it to eyespace
    out += "vec3 normal = normalize(quaternion_rotate(normquat, surface_normal));\n";

    // Gets the index into the specified lookup table for specular lighting
    auto GetLutIndex = [config](unsigned light_num, Regs::LightingLutInput input, bool abs) {
        const std::string half_angle = "normalize(normalize(view) + light_vector)";
        std::string index;
        switch (input) {
        case Regs::LightingLutInput::NH:
            index = "dot(normal, " + half_angle + ")";
            break;

        case Regs::LightingLutInput::VH:
            index = std::string("dot(normalize(view), " + half_angle + ")");
            break;

        case Regs::LightingLutInput::NV:
            index = std::string("dot(normal, normalize(view))");
            break;

        case Regs::LightingLutInput::LN:
            index = std::string("dot(light_vector, normal)");
            break;

        default:
            LOG_CRITICAL(HW_GPU, "Unknown lighting LUT input %d\n", (int)input);
            UNIMPLEMENTED();
            break;
        }

        if (abs) {
            // LUT index is in the range of (0.0, 1.0)
            index = config.lighting.light[light_num].two_sided_diffuse ? "abs(" + index + ")" : "max(" + index + ", 0.f)";
            return "(FLOAT_255 * clamp(" + index + ", 0.0, 1.0))";
        } else {
            // LUT index is in the range of (-1.0, 1.0)
            index = "clamp(" + index + ", -1.0, 1.0)";
            return "(FLOAT_255 * ((" + index + " < 0) ? " + index + " + 2.0 : " + index + ") / 2.0)";
        }

        return std::string();
    };

    // Gets the lighting lookup table value given the specified sampler and index
    auto GetLutValue = [](Regs::LightingSampler sampler, std::string lut_index) {
        return std::string("texture(lut[" + std::to_string((unsigned)sampler / 4) + "], " +
                           lut_index + ")[" + std::to_string((unsigned)sampler & 3) + "]");
    };

    // Write the code to emulate each enabled light
    for (unsigned light_index = 0; light_index < config.lighting.src_num; ++light_index) {
        const auto& light_config = config.lighting.light[light_index];
        std::string light_src = "light_src[" + std::to_string(light_config.num) + "]";

        // Compute light vector (directional or positional)
        if (light_config.directional)
            out += "light_vector = normalize(" + light_src + ".position);\n";
        else
            out += "light_vector = normalize(" + light_src + ".position + view);\n";

        // Compute dot product of light_vector and normal, adjust if lighting is one-sided or two-sided
        std::string dot_product = light_config.two_sided_diffuse ? "abs(dot(light_vector, normal))" : "max(dot(light_vector, normal), 0.0)";

        // If enabled, compute distance attenuation value
        std::string dist_atten = "1.0";
        if (light_config.dist_atten_enable) {
            std::string scale = std::to_string(light_config.dist_atten_scale);
            std::string bias = std::to_string(light_config.dist_atten_bias);
            std::string index = "(" + scale + " * length(-view - " + light_src + ".position) + " + bias + ")";
            index = "((clamp(" + index + ", 0.0, FLOAT_255)))";
            const unsigned lut_num = ((unsigned)Regs::LightingSampler::DistanceAttenuation + light_config.num);
            dist_atten = GetLutValue((Regs::LightingSampler)lut_num, index);
        }

        // If enabled, clamp specular component if lighting result is negative
        std::string clamp_highlights = config.lighting.clamp_highlights ? "(dot(light_vector, normal) <= 0.0 ? 0.0 : 1.0)" : "1.0";

        // Specular 0 component
        std::string d0_lut_value = "1.0";
        if (config.lighting.lut_d0.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::Distribution0)) {
            // Lookup specular "distribution 0" LUT value
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_d0.type, config.lighting.lut_d0.abs_input);
            d0_lut_value = "(" + std::to_string(config.lighting.lut_d0.scale) + " * " + GetLutValue(Regs::LightingSampler::Distribution0, index) + ")";
        }
        std::string specular_0 = "(" + d0_lut_value + " * " + light_src + ".specular_0)";

        // If enabled, lookup ReflectRed value, otherwise, 1.0 is used
        if (config.lighting.lut_rr.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::ReflectRed)) {
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_rr.type, config.lighting.lut_rr.abs_input);
            std::string value = "(" + std::to_string(config.lighting.lut_rr.scale) + " * " + GetLutValue(Regs::LightingSampler::ReflectRed, index) + ")";
            out += "refl_value.r = " + value + ";\n";
        } else {
            out += "refl_value.r = 1.0;\n";
        }

        // If enabled, lookup ReflectGreen value, otherwise, ReflectRed value is used
        if (config.lighting.lut_rg.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::ReflectGreen)) {
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_rg.type, config.lighting.lut_rg.abs_input);
            std::string value = "(" + std::to_string(config.lighting.lut_rg.scale) + " * " + GetLutValue(Regs::LightingSampler::ReflectGreen, index) + ")";
            out += "refl_value.g = " + value + ";\n";
        } else {
            out += "refl_value.g = refl_value.r;\n";
        }

        // If enabled, lookup ReflectBlue value, otherwise, ReflectRed value is used
        if (config.lighting.lut_rb.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::ReflectBlue)) {
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_rb.type, config.lighting.lut_rb.abs_input);
            std::string value = "(" + std::to_string(config.lighting.lut_rb.scale) + " * " + GetLutValue(Regs::LightingSampler::ReflectBlue, index) + ")";
            out += "refl_value.b = " + value + ";\n";
        } else {
            out += "refl_value.b = refl_value.r;\n";
        }

        // Specular 1 component
        std::string d1_lut_value = "1.0";
        if (config.lighting.lut_d1.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::Distribution1)) {
            // Lookup specular "distribution 1" LUT value
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_d1.type, config.lighting.lut_d1.abs_input);
            d1_lut_value = "(" + std::to_string(config.lighting.lut_d1.scale) + " * " + GetLutValue(Regs::LightingSampler::Distribution1, index) + ")";
        }
        std::string specular_1 = "(" + d1_lut_value + " * refl_value * " + light_src + ".specular_1)";

        // Fresnel
        if (config.lighting.lut_fr.enable && Pica::Regs::IsLightingSamplerSupported(config.lighting.config, Pica::Regs::LightingSampler::Fresnel)) {
            // Lookup fresnel LUT value
            std::string index = GetLutIndex(light_config.num, config.lighting.lut_fr.type, config.lighting.lut_fr.abs_input);
            std::string value = "(" + std::to_string(config.lighting.lut_fr.scale) + " * " + GetLutValue(Regs::LightingSampler::Fresnel, index) + ")";

            // Enabled for difffuse lighting alpha component
            if (config.lighting.fresnel_selector == Pica::Regs::LightingFresnelSelector::PrimaryAlpha ||
                config.lighting.fresnel_selector == Pica::Regs::LightingFresnelSelector::Both)
                out += "diffuse_sum.a  *= " + value + ";\n";

            // Enabled for the specular lighting alpha component
            if (config.lighting.fresnel_selector == Pica::Regs::LightingFresnelSelector::SecondaryAlpha ||
                config.lighting.fresnel_selector == Pica::Regs::LightingFresnelSelector::Both)
                out += "specular_sum.a *= " + value + ";\n";
        }

        // Compute primary fragment color (diffuse lighting) function
        out += "diffuse_sum.rgb += ((" + light_src + ".diffuse * " + dot_product + ") + " + light_src + ".ambient) * " + dist_atten + ";\n";

        // Compute secondary fragment color (specular lighting) function
        out += "specular_sum.rgb += (" + specular_0 + " + " + specular_1 + ") * " + clamp_highlights + " * " + dist_atten + ";\n";
    }

    // Sum final lighting result
    out += "diffuse_sum.rgb += lighting_global_ambient;\n";
    out += "primary_fragment_color = clamp(diffuse_sum, vec4(0.0), vec4(1.0));\n";
    out += "secondary_fragment_color = clamp(specular_sum, vec4(0.0), vec4(1.0));\n";
}

std::string GenerateFragmentShader(const PicaShaderConfig& config) {
    std::string out = R"(
#version 330 core
#define NUM_TEV_STAGES 6
#define NUM_LIGHTS 8
#define LIGHTING_LUT_SIZE 256
#define FLOAT_255 (255.0 / 256.0)

in vec4 primary_color;
in vec2 texcoord[3];
in vec4 normquat;
in vec3 view;

out vec4 color;

struct LightSrc {
    vec3 specular_0;
    vec3 specular_1;
    vec3 diffuse;
    vec3 ambient;
    vec3 position;
};

layout (std140) uniform shader_data {
    vec4 const_color[NUM_TEV_STAGES];
    vec4 tev_combiner_buffer_color;
    int alphatest_ref;
    vec3 lighting_global_ambient;
    LightSrc light_src[NUM_LIGHTS];
};

uniform sampler2D tex[3];
uniform sampler1D lut[6];

// Rotate a vector by a quaternion
vec3 quaternion_rotate(vec4 quatertion, vec3 vector) {
    return vector + 2.0 * cross(quatertion.xyz, cross(quatertion.xyz, vector) + quatertion.w * vector);
}

void main() {
vec4 primary_fragment_color = vec4(0.0);
vec4 secondary_fragment_color = vec4(0.0);
)";

    if (config.lighting.enable)
        WriteLighting(out, config);

    // Do not do any sort of processing if it's obvious we're not going to pass the alpha test
    if (config.alpha_test_func == Regs::CompareFunc::Never) {
        out += "discard; }";
        return out;
    }

    out += "vec4 combiner_buffer = vec4(0.0);\n";
    out += "vec4 next_combiner_buffer = tev_combiner_buffer_color;\n";
    out += "vec4 last_tex_env_out = vec4(0.0);\n";

    for (size_t index = 0; index < config.tev_stages.size(); ++index)
        WriteTevStage(out, config, (unsigned)index);

    if (config.alpha_test_func != Regs::CompareFunc::Always) {
        out += "if (";
        AppendAlphaTestCondition(out, config.alpha_test_func);
        out += ") discard;\n";
    }

    out += "color = last_tex_env_out;\n}";

    return out;
}

std::string GenerateVertexShader() {
    std::string out = "#version 330 core\n";

    out += "layout(location = " + std::to_string((int)ATTRIBUTE_POSITION)  + ") in vec4 vert_position;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_COLOR)     + ") in vec4 vert_color;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_TEXCOORD0) + ") in vec2 vert_texcoord0;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_TEXCOORD1) + ") in vec2 vert_texcoord1;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_TEXCOORD2) + ") in vec2 vert_texcoord2;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_NORMQUAT)  + ") in vec4 vert_normquat;\n";
    out += "layout(location = " + std::to_string((int)ATTRIBUTE_VIEW)      + ") in vec3 vert_view;\n";

    out += R"(
out vec4 primary_color;
out vec2 texcoord[3];
out vec4 normquat;
out vec3 view;

void main() {
    primary_color = vert_color;
    texcoord[0] = vert_texcoord0;
    texcoord[1] = vert_texcoord1;
    texcoord[2] = vert_texcoord2;
    normquat = vert_normquat;
    view = vert_view;
    gl_Position = vec4(vert_position.x, vert_position.y, -vert_position.z, vert_position.w);
}
)";

    return out;
}

} // namespace GLShader

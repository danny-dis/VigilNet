package net.vigilnet.app

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Obsidian Design System
object VigilNetTheme {
    val DeepObsidian = Color(0xFF07090D)
    val SurfaceObsidian = Color(0xFF13171F)
    val ElectricCyan = Color(0xFF00E5FF)
    val NeonGreen = Color(0xFF00FFA3)
    val AmberWarning = Color(0xFFFFCC00)
    val FlareRed = Color(0xFFFF4B2B)
    val GlassWhite = Color.White.copy(alpha = 0.1f)
    val GlassStroke = Color.White.copy(alpha = 0.15f)
}

private val DarkColorScheme = darkColorScheme(
    primary = VigilNetTheme.ElectricCyan,
    secondary = VigilNetTheme.NeonGreen,
    tertiary = VigilNetTheme.AmberWarning,
    background = VigilNetTheme.DeepObsidian,
    surface = VigilNetTheme.SurfaceObsidian,
    onPrimary = Color.Black,
    onSecondary = Color.Black,
    onBackground = Color.White,
    onSurface = Color.White.copy(alpha = 0.8f)
)

private val VigilNetTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Black,
        fontSize = 32.sp,
        letterSpacing = (-0.5).sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 24.sp,
        letterSpacing = 0.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        letterSpacing = 1.1.sp
    )
)

@Composable
fun VigilNetAppTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = VigilNetTypography,
        content = content
    )
}

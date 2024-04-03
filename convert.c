/* 
**
** This file is part of Bevara Access Filters.
** 
** This file is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation.
** 
** This file is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License along with this file. If not, see <https://www.gnu.org/licenses/>.
*/


#include <gpac/filters.h>

void convert_rgb_to_rgba(char* rgba, const char* rgb, u32 count) {
    for(int i=0; i<count; ++i) {
        for(int j=0; j<3; ++j) {
            rgba[j] = rgb[j];
        }
		rgba[3] = 255;
        rgba += 4;
        rgb  += 3;
    }
}

void convert_rgba_to_rgb(char* rgb, const char* rgba, u32 count) {
    for(int i=0; i<count; ++i) {
        for(int j=0; j<3; ++j) {
            rgb[j] = rgba[j];
        }
        rgba += 4;
        rgb  += 3;
    }
}

GF_Err convert(char* out, u32 out_format, const char* in, u32 in_format, u32 count){
	if (in_format == GF_PIXEL_RGB && out_format == GF_PIXEL_RGBA ){
		convert_rgb_to_rgba(out, in, count);
	}else if (in_format == GF_PIXEL_RGBA && out_format == GF_PIXEL_RGB ){
		convert_rgba_to_rgb(out, in, count);
	}else {
		return GF_NOT_SUPPORTED;
	}

	return GF_OK;
}
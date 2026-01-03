// Copyright 2023 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opus

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-logr/logr"
	"gopkg.in/hraban/opus.v2"

	"github.com/livekit/protocol/logger"

	"github.com/livekit/media-sdk"
	"github.com/livekit/media-sdk/rtp"
	"github.com/livekit/media-sdk/webm"
)

/*
#cgo pkg-config: opus
#include <opus.h>
*/
import "C"

const SDPName = "opus/48000/2"

var (
	defaultLogger = logger.LogRLogger(logr.Discard())
)

func init() {
	media.RegisterCodec(rtp.NewAudioCodec(media.CodecInfo{
		SDPName:      SDPName,
		SampleRate:   48000,
		RTPClockRate: 48000,
		RTPIsStatic:  false, // Opus uses dynamic payload type
		Priority:     10,    // Higher priority for better quality codec
		FileExt:      "opus",
	}, DecodeRTP, EncodeRTP))
}

type Sample []byte

func (s Sample) Size() int {
	return len(s)
}

func (s Sample) CopyTo(dst []byte) (int, error) {
	if len(dst) < len(s) {
		return 0, io.ErrShortBuffer
	}
	n := copy(dst, s)
	return n, nil
}

type Writer = media.WriteCloser[Sample]

func Decode(w media.PCM16Writer, targetChannels int, logger logger.Logger) (Writer, error) {
	if targetChannels != 1 && targetChannels != 2 {
		return nil, fmt.Errorf("opus decoder only supports mono or stereo output")
	}

	return &decoder{
		w:              w,
		targetChannels: targetChannels,
		lastChannels:   targetChannels,
		logger:         logger,
	}, nil
}

func Encode(w Writer, channels int, logger logger.Logger) (media.PCM16Writer, error) {
	enc, err := opus.NewEncoder(w.SampleRate(), channels, opus.AppVoIP)
	if err != nil {
		return nil, err
	}
	return &encoder{
		w:      w,
		enc:    enc,
		buf:    make([]byte, w.SampleRate()/rtp.DefFramesPerSec*channels),
		logger: logger,
	}, nil
}

type decoder struct {
	w      media.PCM16Writer
	dec    *opus.Decoder
	buf    media.PCM16Sample
	buf2   media.PCM16Sample
	logger logger.Logger

	targetChannels int
	lastChannels   int

	successiveErrorCount int
}

func (d *decoder) String() string {
	return fmt.Sprintf("OPUS(decode) -> %s", d.w)
}

func (d *decoder) SampleRate() int {
	return d.w.SampleRate()
}

func (d *decoder) WriteSample(in Sample) error {
	if len(in) == 0 {
		return nil
	}
	channels, err := d.resetForSample(in)
	if err != nil {
		return err
	}

	n, err := d.dec.Decode(in, d.buf)
	if err != nil {
		// Some workflows (concatenating opus files) can cause a suprious decoding error, so ignore small amount of corruption errors
		if !errors.Is(err, opus.ErrInvalidPacket) || d.successiveErrorCount >= 5 {
			return err
		}
		d.logger.Debugw("opus decoder failed decoding a sample")
		d.successiveErrorCount++
		return nil
	}
	d.successiveErrorCount = 0

	returnData := d.buf[:n*channels]
	if channels < d.targetChannels {
		n2 := len(returnData) * 2
		if len(d.buf2) < n2 {
			d.buf2 = make(media.PCM16Sample, n2)
		}
		media.MonoToStereo(d.buf2, returnData)
		returnData = d.buf2[:n2]
	} else if channels > d.targetChannels {
		n2 := len(returnData) / 2
		if len(d.buf2) < n2 {
			d.buf2 = make(media.PCM16Sample, n2)
		}
		media.StereoToMono(d.buf2, returnData)
		returnData = d.buf2[:n2]
	}

	return d.w.WriteSample(returnData)
}

func (d *decoder) resetForSample(in Sample) (int, error) {
	channels := int(C.opus_packet_get_nb_channels((*C.uchar)(&in[0])))

	if d.dec == nil || d.lastChannels != channels {
		dec, err := opus.NewDecoder(d.w.SampleRate(), channels)
		if err != nil {
			d.logger.Errorw("opus decoder failed to reset", err)
			return 0, err
		}
		d.dec = dec

		d.buf = make([]int16, d.w.SampleRate()/rtp.DefFramesPerSec*channels)
		d.lastChannels = channels
	}

	return channels, nil
}

func (d *decoder) Close() error {
	return d.w.Close()
}

type encoder struct {
	w      Writer
	enc    *opus.Encoder
	buf    Sample
	logger logger.Logger
}

func (e *encoder) String() string {
	return fmt.Sprintf("OPUS(encode) -> %s", e.w)
}

func (e *encoder) SampleRate() int {
	return e.w.SampleRate()
}

func (e *encoder) WriteSample(in media.PCM16Sample) error {
	n, err := e.enc.Encode(in, e.buf)
	if err != nil {
		return err
	}
	return e.w.WriteSample(e.buf[:n])
}

func (e *encoder) Close() error {
	return e.w.Close()
}

func NewWebmWriter(w io.WriteCloser, sampleRate int, channels int, sampleDur time.Duration) media.WriteCloser[Sample] {
	return webm.NewWriter[Sample](w, "A_OPUS", channels, sampleRate, sampleDur)
}

// DecodeRTP creates an Opus decoder for RTP/SIP use.
// It defaults to mono (1 channel) for telephony, but can adapt to stereo if needed.
func DecodeRTP(w media.PCM16Writer) Writer {
	// Resample to 48kHz if needed (Opus standard sample rate)
	if w.SampleRate() != 48000 {
		w = media.ResampleWriter(w, 48000)
	}
	// Default to mono for telephony, but decoder will adapt to packet channels
	// Decode should not fail for valid parameters (48kHz, 1 channel)
	dec, err := Decode(w, 1, defaultLogger)
	if err != nil {
		// This should not happen with valid parameters, but if it does,
		// return a decoder that will fail on first write
		return &errorDecoder{
			w:   w,
			err: fmt.Errorf("failed to create opus decoder: %w", err),
		}
	}
	return dec
}

// errorDecoder is a fallback decoder that returns an error on write
type errorDecoder struct {
	w   media.PCM16Writer
	err error
}

func (d *errorDecoder) String() string {
	return fmt.Sprintf("OPUS(error) -> %s", d.w)
}

func (d *errorDecoder) SampleRate() int {
	return d.w.SampleRate()
}

func (d *errorDecoder) WriteSample(in Sample) error {
	return d.err
}

func (d *errorDecoder) Close() error {
	return d.w.Close()
}

// EncodeRTP creates an Opus encoder for RTP/SIP use.
// It defaults to mono (1 channel) for telephony.
// The writer should be configured for 48kHz sample rate (Opus standard).
func EncodeRTP(w Writer) media.PCM16Writer {
	// Default to mono (1 channel) for telephony
	// Encode should not fail for valid parameters (48kHz, 1 channel)
	enc, err := Encode(w, 1, defaultLogger)
	if err != nil {
		// This should not happen with valid parameters, but if it does,
		// we need to handle it. Since we can't return an error, we'll
		// create an encoder that will fail on first write.
		// In practice, this indicates a configuration error.
		return &errorEncoder{
			w:   w,
			err: fmt.Errorf("failed to create opus encoder: %w", err),
		}
	}
	return enc
}

// errorEncoder is a fallback encoder that returns an error on write
type errorEncoder struct {
	w   Writer
	err error
}

func (e *errorEncoder) String() string {
	return fmt.Sprintf("OPUS(error) -> %s", e.w)
}

func (e *errorEncoder) SampleRate() int {
	return e.w.SampleRate()
}

func (e *errorEncoder) WriteSample(in media.PCM16Sample) error {
	return e.err
}

func (e *errorEncoder) Close() error {
	return e.w.Close()
}

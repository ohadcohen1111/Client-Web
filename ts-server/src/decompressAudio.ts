import { spawn, ChildProcess } from "child_process";
import { Readable, PassThrough } from "stream";
import { logger } from '../logger';

enum Vocoder {
  Amr5_15 = 9,
  Amr12_2 = 47,
}

class AudioDecompressor {
  private static bufferToStream(buffer: Buffer): Readable {
    return new Readable({
      read() {
        this.push(buffer);
        this.push(null);
      },
    });
  }

  private static prependAMRHeader(inputBuffer: Buffer, vocoder: Vocoder): Buffer {
    const amrHeader: number[] = vocoder === Vocoder.Amr12_2
      ? [35, 33, 65, 77, 82, 45, 87, 66, 10]
      : [35, 33, 65, 77, 82, 10];
    const outputBuffer: Buffer = Buffer.alloc(amrHeader.length + inputBuffer.length);
    outputBuffer.set(Buffer.from(amrHeader));
    outputBuffer.set(inputBuffer, amrHeader.length);
    return outputBuffer;
  }

  public static async decompressAudio(inputBuffer: Buffer, vocoder: Vocoder): Promise<Buffer> {
    let sampleRate: number;
    let bitRate: string;

    if (vocoder === Vocoder.Amr5_15) {
      sampleRate = 8000;
      bitRate = "5.15k";
    } else if (vocoder === Vocoder.Amr12_2) {
      sampleRate = 16000;
      bitRate = "12.2k";
    } else {
      const error = new Error(`Unsupported vocoder value: ${vocoder}`);
      logger.error(error.message);
      throw error;
    }

    const bufferWithAmrHeader = this.prependAMRHeader(inputBuffer, vocoder);
    return await this.decodeAMRBuffer(bufferWithAmrHeader, "wav", sampleRate, bitRate);
  }

  private static decodeAMRBuffer(
    inputBuffer: Buffer,
    outputFormat: string = "wav",
    sampleRate: number,
    bitRate: string
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      logger.info('Starting AMR buffer decoding process');
      const inputStream = this.bufferToStream(inputBuffer);
      let outputBuffer = Buffer.alloc(0);

      const ffmpegArgs: string[] = [
        "-f",
        "amr",
        "-i",
        "-",
        "-f",
        outputFormat,
        "-ar",
        sampleRate.toString(),
        "-ab",
        bitRate,
        "-",
      ];

      if (sampleRate === 16000) {
        ffmpegArgs.unshift("-c:a", "libopencore_amrnb");
      }

      logger.info(`FFmpeg arguments: ${ffmpegArgs.join(' ')}`);

      const ffmpegProcess: ChildProcess = spawn("ffmpeg", ffmpegArgs);

      ffmpegProcess.on("error", (err: Error) => {
        logger.error("Failed to start FFmpeg:", err);
        reject(err);
      });

      ffmpegProcess.on("exit", (code: number, signal: string) => {
        if (code !== 0) {
          logger.error(`FFmpeg exited with code ${code}`);
          reject(new Error(`FFmpeg exited with code ${code}`));
        }
      });

      if (ffmpegProcess.stdin) {
        inputStream.pipe(ffmpegProcess.stdin);
      } else {
        const error = new Error("ffmpegProcess.stdin is null");
        logger.error(error.message);
        reject(error);
      }

      if (ffmpegProcess.stdout) {
        ffmpegProcess.stdout.on("data", (chunk: Buffer) => {
          outputBuffer = Buffer.concat([outputBuffer, chunk]);
        });

        ffmpegProcess.stdout.on("end", () => {
          logger.info('AMR buffer decoding process completed successfully');
          resolve(outputBuffer);
        });
      } else {
        const error = new Error("ffmpegProcess.stdout is null");
        logger.error(error.message);
        reject(error);
      }

      if (ffmpegProcess.stderr) {
        ffmpegProcess.stderr.on("data", (data) => {
          // Uncomment the next line if you want to log FFmpeg stderr output
          // logger.debug(`FFmpeg stderr: ${data}`);
        });
      } else {
        const error = new Error("ffmpegProcess.stderr is null");
        logger.error(error.message);
        reject(error);
      }
    });
  }
}

export { AudioDecompressor, Vocoder };
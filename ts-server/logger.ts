const winston = require('winston');
const { combine, timestamp, printf, json, colorize, align } = winston.format;
const DailyRotateFile = require('winston-daily-rotate-file');

const logger = winston.createLogger({
    level: 'http',
    transports: [
        new winston.transports.Console({
            format: combine(
                colorize({ all: true }),
                timestamp({
                  format: 'YYYY-MM-DD hh:mm:ss.SSS A',
                }),
                align(),
                printf((info : any) => `[${info.timestamp}] ${info.level}: ${info.message}`)
              ),
        }),

        new winston.transports.File({
            filename: 'logs/combined.log',
            format: combine(timestamp(), json()),
        }),

        new winston.transports.File({
            filename: 'logs/app-error.log',
            level: 'error',
            format: combine(timestamp(), json()),
        }),

        new winston.transports.File({
            filename: 'logs/app-debug.log',
            level: 'debug',
            format: combine(timestamp(), json()),
        }),

        new DailyRotateFile({
            filename: 'logs/combined-%DATE%.log',
            datePattern: 'YYYY-MM-DD-HH-mm-ss',
            maxFiles: '1', // Keep log files for the last 14 days
            format: combine(timestamp(), json()),
        }),

        new DailyRotateFile({
            filename: 'logs/app-error-%DATE%.log',
            level: 'error',
            datePattern: 'YYYY-MM-DD-HH-mm-ss',
            maxFiles: '1', // Keep log files for the last 14 days
            format: combine(timestamp(), json()),
        }),
    ],
});

export { logger };

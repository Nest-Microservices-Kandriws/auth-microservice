import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { envs, NAST_SERVICE } from 'src/config';


function _getNatsConfig() {
    return ClientsModule.register([
        {
            name: NAST_SERVICE,
            transport: Transport.NATS,
            options: {
                servers: envs.NATS_SERVERS
            },
        },
    ]);
}

@Module({
    imports: [
        _getNatsConfig()
    ],
    exports: [
        _getNatsConfig()
    ],
})
export class NatsModule { }
